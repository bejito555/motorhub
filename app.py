from fastapi import FastAPI, HTTPException, Depends, Request, Response
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

# Load biến môi trường
load_dotenv()

# Cấu hình logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Lấy đường dẫn gốc của dự án
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI()
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "frontend", "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "frontend"))

# Hash mật khẩu
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Kết nối SQLite
DATABASE = os.path.join(BASE_DIR, "mvp50cc.db")

def get_db():
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        logger.error(f"Lỗi kết nối database: {e}")
        raise HTTPException(status_code=500, detail="Kết nối database thất bại")

# Khởi tạo database
def init_db():
    try:
        with get_db() as conn:
            # Kiểm tra và tạo bảng nếu chưa tồn tại
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fullName TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT,
                    last_maintenance_date TEXT
                )
            """)
            # Kiểm tra và thêm cột mobile nếu chưa tồn tại
            try:
                conn.execute("SELECT mobile FROM users LIMIT 1")
            except sqlite3.OperationalError:
                conn.execute("ALTER TABLE users ADD COLUMN mobile TEXT")
            # Kiểm tra và thêm cột location nếu chưa tồn tại
            try:
                conn.execute("SELECT location FROM users LIMIT 1")
            except sqlite3.OperationalError:
                conn.execute("ALTER TABLE users ADD COLUMN location TEXT")
            # Tạo bảng otp_verifications
            conn.execute("""
                CREATE TABLE IF NOT EXISTS otp_verifications (
                    email TEXT PRIMARY KEY,
                    fullName TEXT NOT NULL,
                    password TEXT,
                    otp TEXT NOT NULL,
                    expires_at DATETIME NOT NULL
                )
            """)
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Lỗi khởi tạo database: {e}")
        raise HTTPException(status_code=500, detail="Khởi tạo database thất bại")
init_db()
conn.execute("""
    CREATE TABLE IF NOT EXISTS community_posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
""")
conn.execute("""
    CREATE TABLE IF NOT EXISTS community_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
""")


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

#community
@app.post("/api/community/post")
async def create_post(post: PostCreate, user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Chưa đăng nhập")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO community_posts (user_id, title, content) VALUES (?, ?, ?)",
                       (user["id"], post.title, post.content))
        conn.commit()
    return {"message": "Đăng bài thành công"}
@app.post("/api/community/comment")
async def add_comment(comment: CommentCreate, user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Chưa đăng nhập")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO community_comments (post_id, user_id, content) VALUES (?, ?, ?)",
                       (comment.post_id, user["id"], comment.content))
        conn.commit()
    return {"message": "Bình luận thành công"}
@app.get("/api/community/posts")
async def get_posts():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT p.id, p.title, p.content, p.created_at, u.fullName AS author 
            FROM community_posts p
            JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
        """)
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
        return {"posts": posts}

# Cấu hình JWT và SMTP
SECRET_KEY = os.getenv("SECRET_KEY", "your_secure_random_secret_key")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "902578496557-k0kq281u6g8rv87dk67g3lpdcl5rjqa4.apps.googleusercontent.com")
SMTP_USER = os.getenv("SMTP_USER", "mintatran.01012003@gmail.com")
SMTP_PASS = os.getenv("SMTP_PASS", "fowv uqjv dewq vbzw")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
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

def generate_otp():
    return str(random.randint(100000, 999999))

def check_maintenance_due(last_date):
    if not last_date:
        return "Chưa có lịch bảo trì, hãy đặt lịch!"
    last_date = datetime.strptime(last_date, "%Y-%m-%d")
    due_date = last_date + timedelta(days=30)
    return "Cần bảo trì!" if datetime.utcnow() > due_date else "Bảo trì ổn định"

async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_id = payload.get("sub")
            if not user_id or not user_id.isdigit():
                logger.warning("Invalid user_id in token")
                return None
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, fullName, email, password, last_maintenance_date, mobile, location FROM users WHERE id = ?", (int(user_id),))
                user = cursor.fetchone()
                if user is None:
                    logger.warning(f"No user found with id: {user_id}")
                    return None
                return user
        except JWTError as e:
            logger.warning(f"JWT error: {e}")
            return None
    return None

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
            if not db_user or not db_user["password"] or not verify_password(user.password, db_user["password"]):
                raise HTTPException(status_code=400, detail="Email hoặc mật khẩu không đúng")
            
            access_token = create_access_token(data={"sub": str(db_user["id"])}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
            response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True)
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

@app.post("/api/book_maintenance")
async def book_maintenance(booking: MaintenanceBooking):
    file_path = os.path.join(BASE_DIR, "frontend", "static", "data", "maintenance_bookings.json")
    with open(file_path, "a", encoding="utf-8") as f:
        json.dump({"user_id": booking.user_id, "date": booking.date, "bike_model": booking.bike_model}, f, ensure_ascii=False)
        f.write("\n")
    return {"message": "Lịch bảo dưỡng đã được đặt thành công"}

@app.post("/api/update_profile")
async def update_profile(user_update: UpdateUser, current_user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Token không hợp lệ hoặc thiếu")
    user_id = current_user["id"]
    fullName = user_update.fullName
    email = user_update.email
    password = user_update.password
    mobile = user_update.mobile
    location = user_update.location
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET fullName = ?, email = ?, password = ?, mobile = ?, location = ? WHERE id = ?",
            (fullName, email, get_password_hash(password) if password else current_user["password"], mobile or current_user["mobile"], location or current_user["location"], user_id)
        )
        conn.commit()
    return {"message": f"Đã cập nhật thông tin cho user {user_id}"}

@app.post("/api/reset_password")
async def reset_password(reset: ResetPassword):
    user_id = reset.user_id
    old_password = reset.old_password
    new_password = reset.new_password
    confirm_password = reset.confirm_password

    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="Mật khẩu mới và xác nhận mật khẩu không khớp")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE id = ?", (user_id,))
        db_user = cursor.fetchone()
        if not db_user or not db_user["password"] or not verify_password(old_password, db_user["password"]):
            raise HTTPException(status_code=400, detail="Mật khẩu cũ không đúng")

        hashed_password = get_password_hash(new_password)
        cursor.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (hashed_password, user_id)
        )
        conn.commit()
    return {"message": f"Đã đặt lại mật khẩu cho user {user_id}"}

@app.get("/api/vehicles")
async def get_vehicles():
    vehicles_file = os.path.join(BASE_DIR, "frontend", "static", "data", "vehicles.json")
    if os.path.exists(vehicles_file):
        with open(vehicles_file, "r", encoding="utf-8") as f:
            try:
                vehicles = json.load(f)
                return {"vehicles": vehicles}  # Trả về dictionary trực tiếp
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
        file_path = os.path.join(BASE_DIR, "frontend", "static", "data", "maintenance_bookings.json")
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip().splitlines()
                for line in content:
                    if line.strip():
                        booking = json.loads(line)
                        if str(booking.get("user_id")) == str(user_id):
                            history.append(booking)
        return {"history": history}
    except json.JSONDecodeError as e:
        logger.error(f"Lỗi cú pháp JSON trong maintenance_bookings.json: {e}")
        raise HTTPException(status_code=500, detail="Lỗi cú pháp trong file lịch sử bảo dưỡng")
    except Exception as e:
        logger.error(f"Lỗi khi lấy lịch sử bảo dưỡng: {e}")
        raise HTTPException(status_code=500, detail="Không thể lấy lịch sử bảo dưỡng")

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
async def dashboard_page(request: Request, user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})

@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request, user: Optional[sqlite3.Row] = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse("profile.html", {"request": request, "user": user})

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
    vehicles_data = await get_vehicles()  # Lấy dữ liệu trực tiếp từ get_vehicles
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
    # Dữ liệu hướng dẫn chi tiết cho người dùng, không cần hình ảnh
    guides = [
        {
            "title": "Cách tìm kiếm xe trên Moto50Hub",
            "content": "1. Nhấn vào 'Tìm kiếm' trên menu chính để vào trang tìm kiếm.<br>2. Nhập tên hoặc mô hình xe (ví dụ: Honda SH350i) vào ô tìm kiếm.<br>3. Xem danh sách xe phù hợp với loại, động cơ và giá cả.<br>4. Nhấn 'Chọn xe' để thêm xe vào danh sách cá nhân của bạn.<br><strong>Lưu ý:</strong> Bạn cần đăng nhập để lưu thông tin xe."
        },
        {
            "title": "Cách đặt lịch bảo trì",
            "content": "1. Chọn 'Đặt lịch chăm sóc xe' từ trang chính.<br>2. Chọn ngày bảo trì mong muốn và mô hình xe bạn sở hữu.<br>3. Xác nhận đặt lịch, hệ thống sẽ ghi nhận và gửi thông báo qua email.<br><strong>Lưu ý:</strong> Kiểm tra lịch sử bảo trì trong mục 'Đặt lịch chăm sóc xe' để biết thời gian tiếp theo."
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
