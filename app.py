from fastapi import FastAPI, HTTPException, Depends, Request, Response, UploadFile, File, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
import sqlite3
import os
import logging
import random
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
from google.oauth2 import id_token
from google.auth.transport import requests
import json
import uuid
import shutil
import requests as http_requests
from payos import PayOS, PaymentData, ItemData

# Load biến môi trường
load_dotenv()

# Cấu hình logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Khởi tạo PayOS
payos = PayOS(
    client_id=os.getenv("PAYOS_CLIENT_ID", "b215fa99-4cb1-4c79-b2b1-4037c74a5434"),
    api_key=os.getenv("PAYOS_API_KEY", "d9e06e4a-922d-4bae-999e-ffd92e21724e"),
    checksum_key=os.getenv("PAYOS_CHECKSUM_KEY", "f14ba2be1289c83379ff961a044d651c122ad695c453167ea649ecb8c42f1ef2")
)

# Lấy đường dẫn gốc của dự án
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI()
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "frontend", "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "frontend"))

# Hash mật khẩu
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Kết nối SQLite
DATABASE = os.path.join(BASE_DIR, "mvp50cc.db")
IMAGE_UPLOAD_DIR = os.path.join(BASE_DIR, "frontend", "static", "images")
MAINTENANCE_BOOKINGS_FILE = os.path.join(BASE_DIR, "frontend", "static", "data", "maintenance_bookings.json")

SPARE_PARTS_FILE = os.path.join(BASE_DIR, "frontend", "static", "data", "spare_parts.json")
CART_FILE = os.path.join(BASE_DIR, "frontend", "static", "data", "cart.json")

if not os.path.exists(IMAGE_UPLOAD_DIR):
    os.makedirs(IMAGE_UPLOAD_DIR)
if not os.path.exists(os.path.dirname(MAINTENANCE_BOOKINGS_FILE)):
    os.makedirs(os.path.dirname(MAINTENANCE_BOOKINGS_FILE))
if not os.path.exists(os.path.dirname(SPARE_PARTS_FILE)):
    os.makedirs(os.path.dirname(SPARE_PARTS_FILE))
if not os.path.exists(os.path.dirname(CART_FILE)):
    os.makedirs(os.path.dirname(CART_FILE))

GHN_TOKEN = "8b6e9e38-5ed1-11f0-b272-6641004027c3"  # Token từ GHN
GHN_SHOP_ID = "4852193"  # ShopId từ GHN
GHN_API_URL = "https://dev-online-gateway.ghn.vn/shiip/public-api/v2/shipping-order/create"  # Sandbox, đổi sang production khi triển khai

# Thông tin ngân hàng cố định
BANK_INFO = {
    "bank_name": "Vietcombank",
    "account_number": "1234567890",
    "account_holder": "Nguyen Van A"
}

# Email admin để nhận thông báo
ADMIN_EMAIL = "admin@example.com"

def get_db():
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        logger.error(f"Lỗi kết nối database: {e}")
        raise HTTPException(status_code=500, detail="Kết nối database thất bại")

def init_db():
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fullName TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT,
                    last_maintenance_date TEXT
                )
            """)
            try:
                cursor.execute("SELECT mobile FROM users LIMIT 1")
            except sqlite3.OperationalError:
                cursor.execute("ALTER TABLE users ADD COLUMN mobile TEXT")
            try:
                cursor.execute("SELECT location FROM users LIMIT 1")
            except sqlite3.OperationalError:
                cursor.execute("ALTER TABLE users ADD COLUMN location TEXT")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS otp_verifications (
                    email TEXT PRIMARY KEY,
                    fullName TEXT NOT NULL,
                    password TEXT,
                    otp TEXT NOT NULL,
                    expires_at DATETIME NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS community_posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    image TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS community_comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    post_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS private_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER NOT NULL,
                    receiver_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (sender_id) REFERENCES users(id),
                    FOREIGN KEY (receiver_id) REFERENCES users(id)
                )
            """)
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Lỗi khởi tạo database: {e}")
        raise HTTPException(status_code=500, detail="Khởi tạo database thất bại")

init_db()

# Pydantic models
class UserCreate(BaseModel):
    fullName: str
    email: str
    password: Optional[str] = None

class UserLogin(BaseModel):
    email: str
    password: str

class GoogleLogin(BaseModel):
    token: str

class OTPRequest(BaseModel):
    fullName: str
    email: str
    password: str

class OTPVerify(BaseModel):
    email: str
    otp: str

class MaintenanceBooking(BaseModel):
    user_id: int
    date: str
    bike_model: str
    location: str
    amount: Optional[int] = 2000

class EditMaintenance(BaseModel):
    user_id: int
    booking_id: int
    date: str
    bike_model: str
    location: str

class AddBike(BaseModel):
    user_id: int
    bike_model: str

class SelectBike(BaseModel):
    user_id: int
    bike_id: int

class EditBike(BaseModel):
    user_id: int
    old_model: str
    new_model: str

class DeleteBike(BaseModel):
    user_id: int
    bike_model: str

class UpdateUser(BaseModel):
    user_id: int
    fullName: str
    email: str
    password: Optional[str] = None
    mobile: Optional[str] = None
    location: Optional[str] = None

class ResetPassword(BaseModel):
    user_id: int
    old_password: str
    new_password: str
    confirm_password: str

class PostCreate(BaseModel):
    title: str
    content: str

class CommentCreate(BaseModel):
    post_id: int
    content: str

class PrivateMessageCreate(BaseModel):
    receiver_id: int
    content: str

class RefreshTokenRequest(BaseModel):
    email: str
    password: str

class CartPayment(BaseModel):
    pass

class CartItem(BaseModel):
    spare_part_id: int
    quantity: int

async def get_current_user(request: Request):
    token = request.headers.get("Authorization")
    if token and token.startswith("Bearer "):
        token = token.replace("Bearer ", "")
        logger.debug(f"Token from header: {token}")
    else:
        token = request.cookies.get("access_token")
        logger.debug(f"Token from cookie: {token}")
    if not token:
        logger.warning("No token found in request")
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        logger.debug(f"Decoded payload: {payload}")
        user_id = payload.get("sub")
        if not user_id or not user_id.isdigit():
            logger.warning(f"Invalid user_id in token payload: {user_id}")
            return None
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, fullName, email, password, last_maintenance_date, mobile, location FROM users WHERE id = ?", (int(user_id),))
            user = cursor.fetchone()
            if user is None:
                logger.warning(f"No user found with id: {user_id}")
                return None
            logger.info(f"Authenticated user: {user['id']} with payload: {payload}")
            return user
    except JWTError as e:
        logger.error(f"JWT decoding error: {e}")
        return None

# Community endpoints
@app.post("/api/community/post")
async def create_post(title: str = Form(...), content: str = Form(...), image: UploadFile = File(None), current_user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Vui lòng đăng nhập để đăng bài")
    if not title.strip() or not content.strip():
        raise HTTPException(status_code=400, detail="Tiêu đề và nội dung không được để trống")
    image_path = None
    if image:
        file_extension = image.filename.split('.')[-1]
        unique_filename = f"{uuid.uuid4()}.{file_extension}"
        image_path = os.path.join(IMAGE_UPLOAD_DIR, unique_filename)
        with open(image_path, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)
        image_path = f"/static/images/{unique_filename}"
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO community_posts (user_id, title, content, image) VALUES (?, ?, ?, ?)",
                       (current_user["id"], title.strip(), content.strip(), image_path))
        conn.commit()
    logger.info(f"Post created with ID {cursor.lastrowid} by user {current_user['id']}")
    return {"message": "Đăng bài thành công", "post_id": cursor.lastrowid}

@app.get("/api/spare_parts")
async def get_spare_parts():
    spare_parts_file = os.path.join(BASE_DIR, "frontend", "static", "data", "spare_parts.json")
    if os.path.exists(spare_parts_file):
        with open(spare_parts_file, "r", encoding="utf-8") as f:
            try:
                spare_parts = json.load(f)
                return {"spare_parts": spare_parts}
            except json.JSONDecodeError:
                raise HTTPException(status_code=500, detail="Lỗi đọc file spare_parts.json")
    return {"spare_parts": [], "message": "Không tìm thấy danh sách linh kiện"}

@app.get("/spare_parts", response_class=HTMLResponse)
async def spare_parts_page(request: Request, user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
    spare_parts_data = await get_spare_parts()
    return templates.TemplateResponse("spare_parts.html", {"request": request, "user": user, "spare_parts": spare_parts_data["spare_parts"]})

@app.post("/api/community/comment")
async def add_comment(post_id: int = Form(...), content: str = Form(...), current_user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Vui lòng đăng nhập để bình luận")
    if not content.strip():
        raise HTTPException(status_code=400, detail="Nội dung bình luận không được để trống")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM community_posts WHERE id = ?", (post_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Bài viết không tồn tại")
        cursor.execute("INSERT INTO community_comments (post_id, user_id, content) VALUES (?, ?, ?)",
                       (post_id, current_user["id"], content.strip()))
        conn.commit()
    logger.info(f"Comment added to post {post_id} by user {current_user['id']}")
    return {"message": "Bình luận thành công"}

@app.post("/api/create_payment_link_spare")
async def create_payment_link_spare(request: Request, current_user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not current_user:
        logger.error("User not authenticated")
        raise HTTPException(status_code=401, detail="Vui lòng đăng nhập để tạo liên kết thanh toán")
    
    user_id = current_user["id"]
    logger.debug(f"Processing payment for user_id: {user_id}")
    try:
        cart_items = []
        if os.path.exists(CART_FILE):
            with open(CART_FILE, "r", encoding="utf-8") as f:
                content = f.read().strip().splitlines()
                cart_items = [json.loads(line) for line in content if line.strip()]
        logger.debug(f"Cart items loaded: {cart_items}")
        
        user_cart = [item for item in cart_items if str(item.get("user_id")) == str(user_id) and item.get("payment_status") == "unpaid"]
        logger.debug(f"User cart items: {user_cart}")
        if not user_cart:
            logger.warning("No unpaid items found in cart for user")
            raise HTTPException(status_code=404, detail="Không tìm thấy giỏ hàng của người dùng")

        item = user_cart[0]  # Thanh toán từng linh kiện
        logger.debug(f"Selected item for payment: {item}")
        if os.path.exists(SPARE_PARTS_FILE):
            with open(SPARE_PARTS_FILE, "r", encoding="utf-8") as f:
                spare_parts = json.load(f)
            spare_part = next((part for part in spare_parts if part["id"] == item["spare_part_id"]), None)
            if not spare_part:
                logger.error(f"Spare part not found for id: {item['spare_part_id']}")
                raise HTTPException(status_code=404, detail="Linh kiện không tồn tại")

            total_amount = spare_part["price"] * item["quantity"]
            description = f"Payment for {spare_part['name']} by user {user_id}"
            if len(description) > 25:
                description = description[:25]
            logger.debug(f"Payment details: amount={total_amount}, description={description}")

            order_code = int(f"{item['spare_part_id']}{int(datetime.utcnow().timestamp())}")
            items = [ItemData(name=spare_part["name"], quantity=item["quantity"], price=spare_part["price"])]

            payment_data = PaymentData(
                orderCode=order_code,
                amount=total_amount,
                description=description,
                items=items,
                returnUrl=f"{request.base_url}cart?orderCode={order_code}",
                cancelUrl=f"{request.base_url}cart"
            )
            logger.debug(f"Payment data created: {payment_data.__dict__}")

            result = payos.createPaymentLink(payment_data)
            if result and hasattr(result, 'checkoutUrl'):
                checkout_url = result.checkoutUrl
                logger.info(f"Created payment link for spare_part_id {item['spare_part_id']} of user {user_id} with orderCode {order_code}: {checkout_url}")
                return {"checkout_url": checkout_url}
            else:
                logger.error("Failed to get checkout URL from PayOS")
                raise HTTPException(status_code=500, detail="Không thể lấy URL thanh toán từ PayOS")
    except HTTPException as http_err:
        logger.error(f"HTTP Exception: {http_err.detail}")
        raise http_err
    except Exception as e:
        logger.error(f"Lỗi khi tạo liên kết thanh toán cho giỏ hàng: {str(e)}")
        raise HTTPException(status_code=500, detail="Không thể tạo liên kết thanh toán do lỗi server")
    

@app.post("/api/add_to_cart")
async def add_to_cart(item: CartItem, current_user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Vui lòng đăng nhập để thêm vào giỏ hàng")
    
    user_id = current_user["id"]
    try:
        if os.path.exists(SPARE_PARTS_FILE):
            with open(SPARE_PARTS_FILE, "r", encoding="utf-8") as f:
                spare_parts = json.load(f)
            spare_part = next((part for part in spare_parts if part["id"] == item.spare_part_id), None)
            if not spare_part or spare_part["stock"] < item.quantity:
                raise HTTPException(status_code=400, detail="Linh kiện không tồn tại hoặc số lượng không đủ")

        cart_items = []
        if os.path.exists(CART_FILE):
            with open(CART_FILE, "r", encoding="utf-8") as f:
                content = f.read().strip().splitlines()
                cart_items = [json.loads(line) for line in content if line.strip()]

        cart_item = {"user_id": user_id, "spare_part_id": item.spare_part_id, "quantity": item.quantity, "payment_status": "unpaid"}
        cart_items.append(cart_item)
        with open(CART_FILE, "w", encoding="utf-8") as f:
            for item_data in cart_items:
                json.dump(item_data, f, ensure_ascii=False)
                f.write("\n")

        logger.info(f"Added {item.quantity} of spare_part_id {item.spare_part_id} to cart for user {user_id}")
        return {"message": "Đã thêm linh kiện vào giỏ hàng"}  # Không redirect nữa
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in cart.json: {e}")
        raise HTTPException(status_code=500, detail="Lỗi cú pháp trong file giỏ hàng")
    except Exception as e:
        logger.error(f"Error adding to cart: {e}")
        raise HTTPException(status_code=500, detail="Không thể thêm vào giỏ hàng")

@app.get("/cart", response_class=HTMLResponse)
async def cart_page(request: Request, user: Optional[sqlite3.Row] = Depends(get_current_user), status: str = None, orderCode: str = None):
    if not user:
        return RedirectResponse(url="/login")
    
    user_id = user["id"]
    cart_items = []
    total_amount = 0
    if os.path.exists(CART_FILE):
        with open(CART_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip().splitlines()
            cart_items = [json.loads(line) for line in content if line.strip()]
        user_cart = [item for item in cart_items if str(item.get("user_id")) == str(user_id) and item.get("payment_status") == "unpaid"]  # Chỉ unpaid
        if os.path.exists(SPARE_PARTS_FILE):
            with open(SPARE_PARTS_FILE, "r", encoding="utf-8") as f:
                spare_parts = json.load(f)
            for item in user_cart:
                spare_part = next((part for part in spare_parts if part["id"] == item["spare_part_id"]), None)
                if spare_part:
                    item["name"] = spare_part["name"]
                    item["price"] = spare_part["price"]
                    total_amount += spare_part["price"] * item["quantity"]  # Chỉ tính unpaid

    # ... (giữ nguyên phần cập nhật status và GHN)

    return templates.TemplateResponse("cart.html", {
        "request": request,
        "user": user,
        "cart_items": user_cart,  # Chỉ hiển thị unpaid
        "total_amount": total_amount
    })

@app.get("/api/community/posts")
async def get_posts(user_id: Optional[int] = None):
    with get_db() as conn:
        cursor = conn.cursor()
        query = """
            SELECT p.id, p.user_id, p.title, p.content, p.image, p.created_at, u.fullName AS author 
            FROM community_posts p
            JOIN users u ON p.user_id = u.id
        """
        params = []
        if user_id:
            query += " WHERE p.user_id = ?"
            params.append(user_id)
        query += " ORDER BY p.created_at DESC"
        cursor.execute(query, params)
        posts = [dict(row) for row in cursor.fetchall()]
        for post in posts:
            cursor.execute("""
                SELECT c.content, c.created_at, u.fullName AS commenter 
                FROM community_comments c
                JOIN users u ON c.user_id = u.id
                WHERE c.post_id = ?
                ORDER BY c.created_at ASC
            """, (post["id"],))
            post["comments"] = [dict(c) for c in cursor.fetchall()]
        logger.debug(f"Retrieved {len(posts)} posts")
        return {"posts": posts}

@app.delete("/api/community/post/{post_id}")
async def delete_post(post_id: int, current_user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Vui lòng đăng nhập để xóa bài")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, user_id FROM community_posts WHERE id = ?", (post_id,))
        post = cursor.fetchone()
        if not post:
            raise HTTPException(status_code=404, detail="Bài viết không tồn tại")
        if post["user_id"] != current_user["id"]:
            raise HTTPException(status_code=403, detail="Bạn không có quyền xóa bài viết này")
        cursor.execute("DELETE FROM community_comments WHERE post_id = ?", (post_id,))
        cursor.execute("DELETE FROM community_posts WHERE id = ?", (post_id,))
        conn.commit()
    logger.info(f"Post {post_id} deleted by user {current_user['id']}")
    return {"message": "Xóa bài viết thành công"}

@app.put("/api/community/post/{post_id}")
async def edit_post(post_id: int, title: str = Form(...), content: str = Form(...), image: UploadFile = File(None), current_user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Vui lòng đăng nhập để chỉnh sửa bài")
    if not title.strip() or not content.strip():
        raise HTTPException(status_code=400, detail="Tiêu đề và nội dung không được để trống")
    image_path = None
    if image:
        file_extension = image.filename.split('.')[-1]
        unique_filename = f"{uuid.uuid4()}.{file_extension}"
        image_path = os.path.join(IMAGE_UPLOAD_DIR, unique_filename)
        with open(image_path, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)
        image_path = f"/static/images/{unique_filename}"
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM community_posts WHERE id = ?", (post_id,))
        post_data = cursor.fetchone()
        if not post_data:
            raise HTTPException(status_code=404, detail="Bài viết không tồn tại")
        if post_data["user_id"] != current_user["id"]:
            raise HTTPException(status_code=403, detail="Bạn không có quyền chỉnh sửa bài viết này")
        cursor.execute(
            "UPDATE community_posts SET title = ?, content = ?, image = ? WHERE id = ?",
            (title.strip(), content.strip(), image_path, post_id)
        )
        conn.commit()
    logger.info(f"Post {post_id} edited by user {current_user['id']}")
    return {"message": "Chỉnh sửa bài viết thành công"}

# Private messaging endpoints
@app.post("/api/private_message")
async def send_private_message(message: PrivateMessageCreate, current_user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Vui lòng đăng nhập để gửi tin nhắn")
    if not message.content.strip():
        raise HTTPException(status_code=400, detail="Nội dung tin nhắn không được để trống")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE id = ?", (message.receiver_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Người nhận không tồn tại")
        cursor.execute(
            "INSERT INTO private_messages (sender_id, receiver_id, content) VALUES (?, ?, ?)",
            (current_user["id"], message.receiver_id, message.content.strip())
        )
        conn.commit()
    logger.info(f"Private message sent from user {current_user['id']} to user {message.receiver_id}")
    return {"message": "Gửi tin nhắn thành công"}

@app.get("/api/private_messages")
async def get_private_messages(receiver_id: int, current_user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Vui lòng đăng nhập để xem tin nhắn")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE id = ?", (receiver_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Người nhận không tồn tại")
        cursor.execute("""
            SELECT pm.id, pm.sender_id, pm.receiver_id, pm.content, pm.created_at, u.fullName AS sender_name
            FROM private_messages pm
            JOIN users u ON pm.sender_id = u.id
            WHERE (pm.sender_id = ? AND pm.receiver_id = ?) OR (pm.sender_id = ? AND pm.receiver_id = ?)
            ORDER BY pm.created_at ASC
        """, (current_user["id"], receiver_id, receiver_id, current_user["id"]))
        messages = [dict(row) for row in cursor.fetchall()]
        logger.debug(f"Retrieved {len(messages)} messages between user {current_user['id']} and {receiver_id}")
        return {"messages": messages}

@app.get("/api/users")
async def get_users():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, fullName FROM users")
        users = [dict(row) for row in cursor.fetchall()]
        logger.debug(f"Retrieved {len(users)} users")
        return {"users": users}

# Refresh token endpoint
@app.post("/api/auth/refresh")
async def refresh_token(refresh_request: RefreshTokenRequest, response: Response):
    logger.info(f"Refresh token request for email: {refresh_request.email}")
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password FROM users WHERE email = ?", (refresh_request.email,))
            db_user = cursor.fetchone()
            if not db_user or not db_user["password"] or not verify_password(refresh_request.password, db_user["password"]):
                raise HTTPException(status_code=400, detail="Email hoặc mật khẩu không đúng")
            
            access_token = create_access_token(data={"sub": str(db_user["id"])}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
            response.set_cookie(key="access_token", value=access_token, httponly=True, secure=False)
            logger.info(f"Token refreshed for user {db_user['id']}")
            return {"message": "Token đã được làm mới", "token": access_token}
    except sqlite3.Error as e:
        logger.error(f"Lỗi database khi làm mới token: {e}")
        raise HTTPException(status_code=500, detail="Lỗi làm mới token")

# Cấu hình JWT và SMTP
SECRET_KEY = os.getenv("SECRET_KEY", "your_secure_random_secret_key")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "902578496557-k0kq281u6g8rv87dk67g3lpdcl5rjqa4.apps.googleusercontent.com")
SMTP_USER = os.getenv("SMTP_USER", "mintatran.01012003@gmail.com")
SMTP_PASS = os.getenv("SMTP_PASS", "fowv uqjv dewq vbzw")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.debug(f"Created token with expiry: {expire.strftime('%Y-%m-%d %H:%M:%S')}")
    return encoded_jwt

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def send_otp_email(email: str, otp: str):
    try:
        msg = MIMEText(f"Mã OTP của bạn là: {otp}\nMã này có hiệu lực trong 10 phút.")
        msg['Subject'] = 'Xác minh email cho MotoHub'
        msg['From'] = SMTP_USER
        msg['To'] = email

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        logger.info(f"Gửi OTP đến {email} thành công")
    except Exception as e:
        logger.error(f"Lỗi gửi email OTP: {e}")
        raise HTTPException(status_code=500, detail="Gửi email OTP thất bại")

def send_payment_notification_email(booking_id: int, user_id: int, user_email: str, booking: dict):
    try:
        msg = MIMEText(
            f"Người dùng {user_email} (ID: {user_id}) đã báo cáo hoàn tất thanh toán cho lịch bảo dưỡng:\n\n"
            f"Mã lịch bảo dưỡng: {booking_id}\n"
            f"Ngày: {booking['date']}\n"
            f"Xe: {booking['bike_model']}\n"
            f"Địa điểm: {booking['location']}\n"
            f"Số tiền: {booking.get('amount', 2000)} VND\n\n"
            f"Vui lòng kiểm tra giao dịch ngân hàng và xác nhận thanh toán qua API /api/confirm_payment."
        )
        msg['Subject'] = f'Thông báo thanh toán từ MotoHub - Booking ID {booking_id}'
        msg['From'] = SMTP_USER
        msg['To'] = ADMIN_EMAIL

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        logger.info(f"Gửi thông báo thanh toán đến admin {ADMIN_EMAIL} cho booking_id {booking_id}")
    except Exception as e:
        logger.error(f"Lỗi gửi email thông báo thanh toán: {e}")
        raise HTTPException(status_code=500, detail="Gửi email thông báo thất bại")

def generate_otp():
    return str(random.randint(100000, 999999))

def check_maintenance_due(last_date):
    if not last_date:
        return "Chưa có lịch bảo trì, hãy đặt lịch!"
    last_date = datetime.strptime(last_date, "%Y-%m-%d")
    due_date = last_date + timedelta(days=30)
    return "Cần bảo trì!" if datetime.utcnow() > due_date else "Bảo trì ổn định"

# API routes
@app.post("/api/auth/register/request")
async def request_otp(otp_request: OTPRequest):
    logger.info(f"Nhận yêu cầu OTP: {otp_request.dict()}")
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT email FROM users WHERE email = ?", (otp_request.email,))
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail="Email đã tồn tại")
            
            otp = generate_otp()
            expires_at = datetime.utcnow() + timedelta(minutes=10)
            cursor.execute(
                "INSERT OR REPLACE INTO otp_verifications (email, fullName, password, otp, expires_at) VALUES (?, ?, ?, ?, ?)",
                (otp_request.email, otp_request.fullName, otp_request.password, otp, expires_at)
            )
            conn.commit()
            send_otp_email(otp_request.email, otp)
            return {"message": "Mã OTP đã được gửi đến email của bạn"}
    except sqlite3.Error as e:
        logger.error(f"Lỗi database khi yêu cầu OTP: {e}")
        raise HTTPException(status_code=500, detail="Yêu cầu OTP thất bại do lỗi database")

@app.post("/api/auth/register/verify")
async def verify_otp(otp_verify: OTPVerify, response: Response):
    logger.info(f"Nhận yêu cầu xác minh OTP: {otp_verify.dict()}")
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT otp, expires_at, fullName, password FROM otp_verifications WHERE email = ?",
                (otp_verify.email,)
            )
            result = cursor.fetchone()
            if not result:
                raise HTTPException(status_code=400, detail="Không tìm thấy OTP hoặc OTP đã hết hạn")
            
            if result["otp"] != otp_verify.otp:
                raise HTTPException(status_code=400, detail="Mã OTP không đúng")
            
            if datetime.utcnow() > datetime.strptime(result["expires_at"], "%Y-%m-%d %H:%M:%S.%f"):
                raise HTTPException(status_code=400, detail="Mã OTP đã hết hạn")
            
            hashed_password = get_password_hash(result["password"]) if result["password"] else None
            cursor.execute(
                "INSERT INTO users (fullName, email, password, last_maintenance_date, mobile, location) VALUES (?, ?, ?, ?, ?, ?)",
                (result["fullName"], otp_verify.email, hashed_password, None, None, None)
            )
            conn.commit()
            user_id = cursor.lastrowid
            
            cursor.execute("DELETE FROM otp_verifications WHERE email = ?", (otp_verify.email,))
            conn.commit()
            
            access_token = create_access_token(data={"sub": str(user_id)}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
            response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True)
            logger.info(f"Xác minh OTP và đăng ký thành công, user_id: {user_id}")
            return {"message": "Đăng ký thành công", "token": access_token}
    except sqlite3.Error as e:
        logger.error(f"Lỗi database khi xác minh OTP: {e}")
        raise HTTPException(status_code=500, detail="Xác minh OTP thất bại do lỗi database")

@app.post("/api/auth/google")
async def google_login(google: GoogleLogin, response: Response):
    try:
        idinfo = id_token.verify_oauth2_token(google.token, requests.Request(), GOOGLE_CLIENT_ID)
        email = idinfo['email']
        full_name = idinfo.get('name', email.split('@')[0])
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password FROM users WHERE email = ?", (email,))
            db_user = cursor.fetchone()
            
            if not db_user:
                cursor.execute(
                    "INSERT INTO users (fullName, email, password, last_maintenance_date, mobile, location) VALUES (?, ?, ?, ?, ?, ?)",
                    (full_name, email, None, None, None, None)
                )
                conn.commit()
                user_id = cursor.lastrowid
            else:
                user_id = db_user['id']
            
            access_token = create_access_token(data={"sub": str(user_id)}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
            response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True)
            logger.info(f"Đăng nhập/đăng ký Google thành công, user_id: {user_id}")
            return {"message": "Đăng nhập/đăng ký Google thành công", "token": access_token}
    except ValueError as e:
        logger.error(f"Lỗi xác minh token Google: {e}")
        raise HTTPException(status_code=400, detail="Token Google không hợp lệ")
    except sqlite3.Error as e:
        logger.error(f"Lỗi database khi đăng nhập/đăng ký Google: {e}")
        raise HTTPException(status_code=500, detail="Đăng nhập/đăng ký Google thất bại do lỗi database")

@app.post("/api/auth/login")
async def login(user: UserLogin, response: Response):
    logger.info(f"Nhận dữ liệu đăng nhập: {user.dict()}")
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password FROM users WHERE email = ?", (user.email,))
            db_user = cursor.fetchone()
            if not db_user:
                logger.warning(f"No user found with email: {user.email}")
                raise HTTPException(status_code=400, detail="Email hoặc mật khẩu không đúng")
            if not db_user["password"]:
                logger.warning(f"User {user.email} has no password set")
                raise HTTPException(status_code=400, detail="Tài khoản này chưa có mật khẩu. Vui lòng đặt mật khẩu qua trang hồ sơ.")
            if not verify_password(user.password, db_user["password"]):
                logger.warning(f"Password verification failed for user: {user.email}")
                raise HTTPException(status_code=400, detail="Email hoặc mật khẩu không đúng")
            
            access_token = create_access_token(data={"sub": str(db_user["id"])}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
            response.set_cookie(key="access_token", value=access_token, httponly=False, secure=True)  # Đổi httponly=False cho test
            logger.info(f"Đăng nhập thành công, user_id: {db_user['id']}")
            return {"message": "Đăng nhập thành công", "token": access_token}
    except sqlite3.Error as e:
        logger.error(f"Lỗi database khi đăng nhập: {e}")
        raise HTTPException(status_code=500, detail="Đăng nhập thất bại do lỗi database")

@app.get("/api/auth/user")
async def get_user(current_user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Token không hợp lệ hoặc thiếu")
    return {"id": current_user["id"], "fullName": current_user["fullName"], "email": current_user["email"], "last_maintenance_date": current_user["last_maintenance_date"], "mobile": current_user["mobile"], "location": current_user["location"]}

@app.post("/api/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Đăng xuất thành công"}

@app.post("/api/remove_from_cart")
async def remove_from_cart(item: CartItem, current_user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Vui lòng đăng nhập để xóa khỏi giỏ hàng")
    
    user_id = current_user["id"]
    try:
        cart_items = []
        if os.path.exists(CART_FILE):
            with open(CART_FILE, "r", encoding="utf-8") as f:
                content = f.read().strip().splitlines()
                cart_items = [json.loads(line) for line in content if line.strip()]

        # Xóa item phù hợp với user_id và spare_part_id
        new_cart_items = [item_data for item_data in cart_items if not (str(item_data.get("user_id")) == str(user_id) and item_data.get("spare_part_id") == item.spare_part_id)]

        if len(new_cart_items) < len(cart_items):
            with open(CART_FILE, "w", encoding="utf-8") as f:
                for item_data in new_cart_items:
                    json.dump(item_data, f, ensure_ascii=False)
                    f.write("\n")
            logger.info(f"Removed spare_part_id {item.spare_part_id} from cart for user {user_id}")
            return {"message": "Đã xóa linh kiện khỏi giỏ hàng"}
        else:
            raise HTTPException(status_code=404, detail="Không tìm thấy linh kiện trong giỏ hàng")
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in cart.json: {e}")
        raise HTTPException(status_code=500, detail="Lỗi cú pháp trong file giỏ hàng")
    except Exception as e:
        logger.error(f"Error removing from cart: {e}")
        raise HTTPException(status_code=500, detail="Không thể xóa khỏi giỏ hàng")

# PayOS endpoints
@app.post("/api/create_payment_link")
async def create_payment_link(data: dict, request: Request, current_user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Vui lòng đăng nhập để tạo liên kết thanh toán")
    
    booking_id = data.get("booking_id")
    user_id = data.get("user_id")
    
    try:
        file_path = MAINTENANCE_BOOKINGS_FILE
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip().splitlines()
                bookings = [json.loads(line) for line in content if line.strip()]
            if 0 <= booking_id < len(bookings) and str(bookings[booking_id].get("user_id")) == str(user_id):
                booking = bookings[booking_id]
                payment_status = booking.get("payment_status", "unpaid")
                if payment_status == "paid":
                    raise HTTPException(status_code=400, detail="Lịch đặt xe đã được thanh toán")
                
                description = f"Payment #{booking_id}"
                if len(description) > 25:
                    raise HTTPException(status_code=400, detail="Mô tả thanh toán quá dài")

                order_code = int(f"{booking_id}{int(datetime.utcnow().timestamp())}")
                amount = booking.get("amount", 20000)
                items = [ItemData(name=booking["bike_model"], quantity=1, price=amount)]
                
                payment_data = PaymentData(
                    orderCode=order_code,
                    amount=amount,
                    description=description,
                    items=items,
                    returnUrl=f"{request.base_url}dashboard?orderCode={order_code}",  # Truyền orderCode trong redirect
                    cancelUrl=f"{request.base_url}payment/{booking_id}"
                )
                
                result = payos.createPaymentLink(payment_data)
                if result and hasattr(result, 'checkoutUrl'):
                    checkout_url = result.checkoutUrl
                    logger.info(f"Created payment link for booking_id {booking_id}: {checkout_url}")
                    return {"checkout_url": checkout_url}
                else:
                    raise HTTPException(status_code=500, detail="Không thể lấy URL thanh toán từ PayOS")
            else:
                raise HTTPException(status_code=404, detail="Lịch đặt xe không tồn tại hoặc không thuộc về người dùng")
        else:
            raise HTTPException(status_code=404, detail="Không tìm thấy dữ liệu lịch đặt xe")
    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        logger.error(f"Lỗi khi tạo liên kết thanh toán: {e}")
        raise HTTPException(status_code=500, detail="Không thể tạo liên kết thanh toán do lỗi server")

@app.post("/api/webhook/payos")
async def payos_webhook(data: dict):
    try:
        # Xác minh webhook từ PayOS
        webhook_data = payos.verifyPaymentWebhookData(data)
        if webhook_data["code"] != "00":
            logger.warning(f"Webhook thanh toán không thành công: {webhook_data}")
            return JSONResponse(status_code=400, content={"message": "Thanh toán không thành công"})

        order_code = webhook_data["orderCode"]
        booking_id = int(str(order_code)[:-10])  # Lấy booking_id từ order_code
        user_id = webhook_data["desc"].split(" - ")[0].split()[-1]  # Lấy user_id từ description

        # Cập nhật trạng thái thanh toán
        file_path = os.path.join(BASE_DIR, "frontend", "static", "data", "maintenance_bookings.json")
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip().splitlines()
                bookings = [json.loads(line) for line in content if line.strip()]
            if 0 <= booking_id < len(bookings) and str(bookings[booking_id].get("user_id")) == str(user_id):
                bookings[booking_id]["payment_status"] = "paid"
                with open(file_path, "w", encoding="utf-8") as f:
                    for booking in bookings:
                        json.dump(booking, f, ensure_ascii=False)
                        f.write("\n")
                logger.info(f"Webhook: Payment confirmed for booking_id {booking_id}")
                return {"message": "Xác nhận thanh toán thành công"}
            else:
                logger.error(f"Webhook: Booking {booking_id} not found or does not belong to user {user_id}")
                return JSONResponse(status_code=404, content={"message": "Lịch đặt xe không tồn tại hoặc không thuộc về người dùng"})
        else:
            logger.error(f"Webhook: Maintenance bookings file not found at {file_path}")
            return JSONResponse(status_code=404, content={"message": "Không tìm thấy dữ liệu lịch đặt xe"})
    except Exception as e:
        logger.error(f"Lỗi xử lý webhook PayOS: {e}")
        return JSONResponse(status_code=500, content={"message": "Lỗi xử lý webhook"})

# API routes khác
@app.post("/api/add_bike")
async def add_bike(bike: AddBike):
    user_id = bike.user_id
    bike_model = bike.bike_model
    file_path = os.path.join(BASE_DIR, "frontend", "static", "data", "user_bikes.json")
    with open(file_path, "a", encoding="utf-8") as f:
        json.dump({"user_id": user_id, "bike_model": bike_model}, f, ensure_ascii=False)
        f.write("\n")
    return {"message": f"Đã thêm xe {bike_model} cho user {user_id}"}

@app.post("/api/select_bike")
async def select_bike(bike: SelectBike):
    user_id = bike.user_id
    bike_id = bike.bike_id
    vehicles_file = os.path.join(BASE_DIR, "frontend", "static", "data", "vehicles.json")
    if os.path.exists(vehicles_file):
        with open(vehicles_file, "r", encoding="utf-8") as f:
            try:
                vehicles = json.load(f)
            except json.JSONDecodeError:
                raise HTTPException(status_code=500, detail="Lỗi đọc file JSON")
        selected_bike = next((vehicle for vehicle in vehicles if vehicle["id"] == bike_id), None)
        if selected_bike:
            bike_model = selected_bike["name"]
            bike_image = selected_bike.get("image", "no-image.jpg")
            file_path = os.path.join(BASE_DIR, "frontend", "static", "data", "user_bikes.json")
            new_bike = {"user_id": user_id, "bike_model": bike_model, "image": bike_image}
            if os.path.exists(file_path):
                with open(file_path, "r", encoding="utf-8") as f:
                    try:
                        data = json.load(f)
                        if not isinstance(data, list):
                            data = []
                    except json.JSONDecodeError:
                        data = []
            else:
                data = []
            data.append(new_bike)
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
            return {"message": f"Đã chọn xe {bike_model} cho user {user_id}"}
    raise HTTPException(status_code=404, detail="Xe không tồn tại")

@app.post("/api/edit_bike")
async def edit_bike(bike: EditBike):
    user_id = bike.user_id
    old_model = bike.old_model
    new_model = bike.new_model
    file_path = os.path.join(BASE_DIR, "frontend", "static", "data", "user_bikes.json")
    try:
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                bikes = json.loads(content) if content else []
                if not isinstance(bikes, list):
                    bikes = []
        else:
            bikes = []
        
        updated = False
        vehicles_file = os.path.join(BASE_DIR, "frontend", "static", "data", "vehicles.json")
        new_image = "no-image.jpg"
        if os.path.exists(vehicles_file):
            with open(vehicles_file, "r", encoding="utf-8") as f:
                vehicles = json.load(f)
                selected_vehicle = next((v for v in vehicles if v["name"] == new_model), None)
                if selected_vehicle:
                    new_image = selected_vehicle.get("image", "no-image.jpg")

        for bike_data in bikes:
            if str(bike_data["user_id"]) == str(user_id) and bike_data["bike_model"] == old_model:
                bike_data["bike_model"] = new_model
                bike_data["image"] = new_image
                updated = True
        
        if updated:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(bikes, f, ensure_ascii=False, indent=4)
            return {"message": f"Đã chỉnh sửa xe {old_model} thành {new_model} cho user {user_id}"}
        else:
            return {"message": "Không tìm thấy xe để chỉnh sửa"}
    except json.JSONDecodeError as e:
        logger.error(f"Lỗi cú pháp JSON trong user_bikes.json: {e}")
        raise HTTPException(status_code=500, detail="Lỗi cú pháp trong file dữ liệu xe")
    except Exception as e:
        logger.error(f"Lỗi khi chỉnh sửa xe: {e}")
        raise HTTPException(status_code=500, detail="Không thể chỉnh sửa xe")

@app.post("/api/delete_bike")
async def delete_bike(bike: DeleteBike):
    user_id = bike.user_id
    bike_model = bike.bike_model
    file_path = os.path.join(BASE_DIR, "frontend", "static", "data", "user_bikes.json")
    try:
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                bikes = json.loads(content) if content else []
                if not isinstance(bikes, list):
                    bikes = []
        else:
            bikes = []
        
        new_bikes = [bike_data for bike_data in bikes if not (str(bike_data["user_id"]) == str(user_id) and bike_data["bike_model"] == bike_model)]
        
        if len(new_bikes) < len(bikes):
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(new_bikes, f, ensure_ascii=False, indent=4)
            return {"message": f"Đã xóa xe {bike_model} cho user {user_id}"}
        else:
            return {"message": "Không tìm thấy xe để xóa"}
    except json.JSONDecodeError as e:
        logger.error(f"Lỗi cú pháp JSON trong user_bikes.json: {e}")
        raise HTTPException(status_code=500, detail="Lỗi cú pháp trong file dữ liệu xe")
    except Exception as e:
        logger.error(f"Lỗi khi xóa xe: {e}")
        raise HTTPException(status_code=500, detail="Không thể xóa xe")

@app.get("/api/vehicles")
async def get_vehicles():
    vehicles_file = os.path.join(BASE_DIR, "frontend", "static", "data", "vehicles.json")
    if os.path.exists(vehicles_file):
        with open(vehicles_file, "r", encoding="utf-8") as f:
            try:
                vehicles = json.load(f)
                return {"vehicles": vehicles}
            except json.JSONDecodeError:
                raise HTTPException(status_code=500, detail="Lỗi đọc file vehicles.json")
    else:
        return {"vehicles": [], "message": "Không tìm thấy danh sách xe"}

@app.get("/api/user_bikes")
async def get_user_bikes(user_id: int):
    try:
        bikes = []
        file_path = os.path.join(BASE_DIR, "frontend", "static", "data", "user_bikes.json")
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    data = json.loads(content)
                    if isinstance(data, list):
                        bikes = [bike for bike in data if str(bike.get("user_id")) == str(user_id)]
        return {"bikes": bikes}
    except json.JSONDecodeError as e:
        logger.error(f"Lỗi cú pháp JSON trong user_bikes.json: {e}")
        raise HTTPException(status_code=500, detail="Lỗi cú pháp trong file dữ liệu xe")
    except Exception as e:
        logger.error(f"Lỗi khi lấy danh sách xe của người dùng: {e}")
        raise HTTPException(status_code=500, detail="Không thể lấy danh sách xe")

@app.get("/api/maintenance_history")
async def get_maintenance_history(user_id: int):
    try:
        history = []
        file_path = MAINTENANCE_BOOKINGS_FILE
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip().splitlines()
                for index, line in enumerate(content):
                    if line.strip():
                        booking = json.loads(line)
                        if str(booking.get("user_id")) == str(user_id):
                            booking["id"] = index
                            history.append(booking)
        logger.debug(f"Maintenance history for user {user_id}: {history}")
        return {"history": history}
    except json.JSONDecodeError as e:
        logger.error(f"Lỗi cú pháp JSON trong maintenance_bookings.json: {e}")
        raise HTTPException(status_code=500, detail="Lỗi cú pháp trong file lịch sử bảo dưỡng")
    except Exception as e:
        logger.error(f"Lỗi khi lấy lịch sử bảo dưỡng: {e}")
        raise HTTPException(status_code=500, detail="Không thể lấy lịch sử bảo dưỡng")

@app.delete("/api/delete_maintenance")
async def delete_maintenance(user_id: int, booking_id: int):
    file_path = MAINTENANCE_BOOKINGS_FILE
    logger.debug(f"Attempting to delete booking {booking_id} for user {user_id}")
    try:
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip().splitlines()
                bookings = [json.loads(line) for line in content if line.strip()]
            if 0 <= booking_id < len(bookings) and str(bookings[booking_id].get("user_id")) == str(user_id):
                del bookings[booking_id]
                with open(file_path, "w", encoding="utf-8") as f:
                    for booking in bookings:
                        json.dump(booking, f, ensure_ascii=False)
                        f.write("\n")
                logger.info(f"Successfully deleted booking {booking_id} for user {user_id}")
                return {"message": "Đã xóa lịch đặt xe thành công"}
            logger.warning(f"Booking {booking_id} not found or does not belong to user {user_id}")
            raise HTTPException(status_code=404, detail="Lịch đặt xe không tồn tại hoặc không thuộc về người dùng")
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in maintenance_bookings.json: {e}")
        raise HTTPException(status_code=500, detail="Lỗi cú pháp trong file lịch sử bảo dưỡng")
    except Exception as e:
        logger.error(f"Error deleting maintenance booking: {e}")
        raise HTTPException(status_code=500, detail="Không thể xóa lịch đặt xe")

@app.post("/api/edit_maintenance")
async def edit_maintenance(edit: EditMaintenance):
    file_path = MAINTENANCE_BOOKINGS_FILE
    logger.debug(f"Attempting to edit booking {edit.booking_id} for user {edit.user_id} with data: {edit.dict()}")
    try:
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip().splitlines()
                bookings = [json.loads(line) for line in content if line.strip()]
            if 0 <= edit.booking_id < len(bookings) and str(bookings[edit.booking_id].get("user_id")) == str(edit.user_id):
                bookings[edit.booking_id]["date"] = edit.date
                bookings[edit.booking_id]["bike_model"] = edit.bike_model
                bookings[edit.booking_id]["location"] = edit.location
                with open(file_path, "w", encoding="utf-8") as f:
                    for booking in bookings:
                        json.dump(booking, f, ensure_ascii=False)
                        f.write("\n")
                logger.info(f"Successfully edited booking {edit.booking_id} for user {edit.user_id}")
                return {"message": "Đã chỉnh sửa lịch đặt xe thành công"}
            logger.warning(f"Booking {edit.booking_id} not found or does not belong to user {edit.user_id}")
            raise HTTPException(status_code=404, detail="Lịch đặt xe không tồn tại hoặc không thuộc về người dùng")
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in maintenance_bookings.json: {e}")
        raise HTTPException(status_code=500, detail="Lỗi cú pháp trong file lịch sử bảo dưỡng")
    except Exception as e:
        logger.error(f"Error editing maintenance booking: {e}")
        raise HTTPException(status_code=500, detail="Không thể chỉnh sửa lịch đặt xe")

@app.post("/api/confirm_payment")
async def confirm_payment(data: dict):
    booking_id = data.get("booking_id")
    user_id = data.get("user_id")
    logger.debug(f"Admin confirming payment for booking_id {booking_id}, user_id {user_id}")
    
    try:
        file_path = MAINTENANCE_BOOKINGS_FILE
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip().splitlines()
                bookings = [json.loads(line) for line in content if line.strip()]
            if 0 <= booking_id < len(bookings) and str(bookings[booking_id].get("user_id")) == str(user_id):
                if bookings[booking_id]["payment_status"] == "paid":
                    logger.warning(f"Booking {booking_id} already paid")
                    raise HTTPException(status_code=400, detail="Lịch đặt xe đã được thanh toán")
                bookings[booking_id]["payment_status"] = "paid"
                with open(file_path, "w", encoding="utf-8") as f:
                    for booking in bookings:
                        json.dump(booking, f, ensure_ascii=False)
                        f.write("\n")
                logger.info(f"Payment confirmed for booking_id {booking_id}")
                return {"message": "Xác nhận thanh toán thành công"}
            else:
                logger.error(f"Booking {booking_id} not found or does not belong to user {user_id}")
                raise HTTPException(status_code=404, detail="Lịch đặt xe không tồn tại hoặc không thuộc về người dùng")
        else:
            logger.error(f"Maintenance bookings file not found at {file_path}")
            raise HTTPException(status_code=404, detail="Không tìm thấy dữ liệu lịch đặt xe")
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in maintenance_bookings.json: {e}")
        raise HTTPException(status_code=500, detail="Lỗi cú pháp trong file lịch sử bảo dưỡng")
    except Exception as e:
        logger.error(f"Error confirming payment: {e}")
        raise HTTPException(status_code=500, detail="Không thể xác nhận thanh toán")

@app.get("/api/check_payment_status")
async def check_payment_status(booking_id: int, user_id: int):
    logger.debug(f"Checking payment status for booking_id {booking_id}, user_id {user_id}")
    try:
        file_path = MAINTENANCE_BOOKINGS_FILE
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip().splitlines()
                bookings = [json.loads(line) for line in content if line.strip()]
            if 0 <= booking_id < len(bookings) and str(bookings[booking_id].get("user_id")) == str(user_id):
                return {"payment_status": bookings[booking_id]["payment_status"]}
            else:
                logger.error(f"Booking {booking_id} not found or does not belong to user {user_id}")
                raise HTTPException(status_code=404, detail="Lịch đặt xe không tồn tại hoặc không thuộc về người dùng")
        else:
            logger.error(f"Maintenance bookings file not found at {file_path}")
            raise HTTPException(status_code=404, detail="Không tìm thấy dữ liệu lịch đặt xe")
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in maintenance_bookings.json: {e}")
        raise HTTPException(status_code=500, detail="Lỗi cú pháp trong file lịch sử bảo dưỡng")
    except Exception as e:
        logger.error(f"Error checking payment status: {e}")
        raise HTTPException(status_code=500, detail="Không thể kiểm tra trạng thái thanh toán")

@app.post("/api/notify_payment")
async def notify_payment(data: dict, current_user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Vui lòng đăng nhập để thông báo thanh toán")
    booking_id = data.get("booking_id")
    user_id = data.get("user_id")
    logger.debug(f"User {user_id} notifying payment for booking_id {booking_id}")
    
    try:
        file_path = MAINTENANCE_BOOKINGS_FILE
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip().splitlines()
                bookings = [json.loads(line) for line in content if line.strip()]
            if 0 <= booking_id < len(bookings) and str(bookings[booking_id].get("user_id")) == str(user_id):
                booking = bookings[booking_id]
                if booking["payment_status"] == "paid":
                    logger.warning(f"Booking {booking_id} already paid")
                    raise HTTPException(status_code=400, detail="Lịch đặt xe đã được thanh toán")
                send_payment_notification_email(booking_id, user_id, current_user["email"], booking)
                logger.info(f"Payment notification sent for booking_id {booking_id}")
                return {"message": "Thông báo thanh toán đã được gửi đến admin. Vui lòng thanh toán qua PayOS."}
            else:
                logger.error(f"Booking {booking_id} not found or does not belong to user {user_id}")
                raise HTTPException(status_code=404, detail="Lịch đặt xe không tồn tại hoặc không thuộc về người dùng")
        else:
            logger.error(f"Maintenance bookings file not found at {file_path}")
            raise HTTPException(status_code=404, detail="Không tìm thấy dữ liệu lịch đặt xe")
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in maintenance_bookings.json: {e}")
        raise HTTPException(status_code=500, detail="Lỗi cú pháp trong file lịch sử bảo dưỡng")
    except Exception as e:
        logger.error(f"Error sending payment notification: {e}")
        raise HTTPException(status_code=500, detail="Không thể gửi thông báo thanh toán")

@app.get("/payment/{booking_id}", response_class=HTMLResponse)
async def payment_page(request: Request, booking_id: int, user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not user:
        logger.warning("User not authenticated, redirecting to login")
        return RedirectResponse(url="/login")
    
    try:
        file_path = MAINTENANCE_BOOKINGS_FILE
        logger.debug(f"Attempting to load maintenance bookings from {file_path} for booking_id {booking_id}")
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip().splitlines()
                bookings = [json.loads(line) for line in content if line.strip()]
            if 0 <= booking_id < len(bookings) and str(bookings[booking_id].get("user_id")) == str(user["id"]):
                booking = bookings[booking_id]
                booking["id"] = booking_id
                logger.info(f"Rendering payment page for booking_id {booking_id}, user_id {user['id']}")
                return templates.TemplateResponse("payment.html", {
                    "request": request,
                    "user": user,
                    "booking": booking,
                    "booking_id": booking_id,
                    "amount": booking.get("amount", 2000),
                    "bank_info": BANK_INFO
                })
            else:
                logger.error(f"Booking {booking_id} not found or does not belong to user {user['id']}")
                raise HTTPException(status_code=404, detail="Lịch đặt xe không tồn tại hoặc không thuộc về người dùng")
        else:
            logger.error(f"Maintenance bookings file not found at {file_path}")
            raise HTTPException(status_code=404, detail="Không tìm thấy dữ liệu lịch đặt xe")
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in maintenance_bookings.json: {e}")
        raise HTTPException(status_code=500, detail="Lỗi cú pháp trong file lịch sử bảo dưỡng")
    except Exception as e:
        logger.error(f"Error loading payment page for booking_id {booking_id}: {e}")
        raise HTTPException(status_code=500, detail="Không thể lấy thông tin thanh toán")

# Web routes
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, user: Optional[sqlite3.Row] = Depends(get_current_user)):
    return templates.TemplateResponse("index.html", {"request": request, "user": user})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    user = await get_current_user(request)
    if user:
        return RedirectResponse(url="/dashboard")
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    user = await get_current_user(request)
    if user:
        return RedirectResponse(url="/dashboard")
    return templates.TemplateResponse("signup.html", {"request": request})

@app.get("/verify-email", response_class=HTMLResponse)
async def verify_email_page(request: Request, email: Optional[str] = None):
    user = await get_current_user(request)
    if user:
        return RedirectResponse(url="/dashboard")
    return templates.TemplateResponse("verify_email.html", {"request": request, "email": email})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request, user: Optional[sqlite3.Row] = Depends(get_current_user), status: str = None, orderCode: str = None):
    if not user:
        return RedirectResponse(url="/login")
    
    # Kiểm tra tham số status từ PayOS redirect
    if status == "PAID" and orderCode and orderCode.strip():
        try:
            # Lấy booking_id (index) từ orderCode
            booking_id = int(str(orderCode)[:-10])  # Suy ra index từ phần đầu của orderCode
            file_path = MAINTENANCE_BOOKINGS_FILE
            if os.path.exists(file_path):
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read().strip().splitlines()
                    bookings = [json.loads(line) for line in content if line.strip()]
                if 0 <= booking_id < len(bookings) and str(bookings[booking_id].get("user_id")) == str(user["id"]):
                    bookings[booking_id]["payment_status"] = "paid"
                    with open(file_path, "w", encoding="utf-8") as f:
                        for booking in bookings:
                            json.dump(booking, f, ensure_ascii=False)
                            f.write("\n")
                    logger.info(f"Payment status updated to 'paid' for booking_id {booking_id} via dashboard")
        except ValueError as e:
            logger.error(f"Error updating payment status in dashboard: Invalid orderCode {orderCode}: {e}")
        except Exception as e:
            logger.error(f"Error updating payment status in dashboard: {e}")

    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})

@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request, user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
    history = await get_maintenance_history(user["id"])
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "user": user,
        "history": history["history"]
    })

@app.get("/maintenance", response_class=HTMLResponse)
async def maintenance_page(request: Request, user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
    maintenance_due = check_maintenance_due(user["last_maintenance_date"]) if user["last_maintenance_date"] else None
    history = await get_maintenance_history(user["id"])
    return templates.TemplateResponse("maintenance.html", {"request": request, "user": user, "maintenance_due": maintenance_due, "history": history["history"]})

@app.get("/search", response_class=HTMLResponse)
async def search_page(request: Request, user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
    vehicles_data = await get_vehicles()
    return templates.TemplateResponse("search.html", {"request": request, "user": user, "vehicles": vehicles_data["vehicles"]})

@app.get("/custom3d", response_class=HTMLResponse)
async def custom3d_page(request: Request, user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse("custom3d.html", {"request": request, "user": user})

@app.get("/community", response_class=HTMLResponse)
async def community_page(request: Request, user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse("community.html", {"request": request, "user": user})

@app.get("/promotion", response_class=HTMLResponse)
async def promotion_page(request: Request, user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse("promotion.html", {"request": request, "user": user})

@app.get("/instruction", response_class=HTMLResponse)
async def instruction_page(request: Request, user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
    guides = [
        {
            "title": "Cách tìm kiếm xe trên Moto50Hub",
            "content": "1. Nhấn vào 'Tìm kiếm' trên menu chính để vào trang tìm kiếm.<br>2. Nhập tên hoặc mô hình xe (ví dụ: Honda SH350i) vào ô tìm kiếm.<br>3. Xem danh sách xe phù hợp với loại, động cơ và giá cả.<br>4. Nhấn 'Chọn xe' để thêm xe vào danh sách cá nhân của bạn.<br><strong>Lưu ý:</strong> Bạn cần đăng nhập để lưu thông tin xe."
        },
        {
            "title": "Cách đặt lịch bảo trì",
            "content": "1. Chọn 'Đặt lịch chăm sóc xe' từ trang chính.<br>2. Chọn ngày bảo trì mong muốn, mô hình xe và địa điểm.<br>3. Xác nhận đặt lịch, hệ thống sẽ ghi nhận và gửi thông báo qua email.<br><strong>Lưu ý:</strong> Kiểm tra lịch sử bảo trì trong mục 'Đặt lịch chăm sóc xe' để biết thời gian tiếp theo."
        },
        {
            "title": "Cách tùy chỉnh xe 3D",
            "content": "1. Vào trang 'Tùy chỉnh 3D' từ menu.<br>2. Chọn xe từ danh sách và thay đổi màu sắc hoặc phụ kiện.<br>3. Lưu thiết kế của bạn để sử dụng sau này.<br><strong>Lưu ý:</strong> Đảm bảo có kết nối internet ổn định để trải nghiệm tốt nhất."
        },
        {
            "title": "Cách tham gia cộng đồng",
            "content": "1. Truy cập 'Cộng đồng' từ menu chính.<br>2. Đăng bài viết hoặc bình luận để chia sẻ kinh nghiệm.<br>3. Kết nối với người dùng khác qua các chủ đề phổ biến.<br><strong>Lưu ý:</strong> Tuân thủ quy định cộng đồng để tránh bị hạn chế quyền truy cập."
        },
        {
            "title": "Cách cập nhật hồ sơ tài khoản",
            "content": "1. Nhấn vào 'Hồ sơ tài khoản' từ menu.<br>2. Nhấn 'Save Change' để chỉnh sửa thông tin (tên, email, số điện thoại, địa chỉ).<br>3. Lưu thay đổi để cập nhật thông tin cá nhân.<br><strong>Lưu ý:</strong> Đảm bảo thông tin chính xác để nhận thông báo từ hệ thống."
        }
    ]
    return templates.TemplateResponse("instruction.html", {"request": request, "user": user, "guides": guides})
