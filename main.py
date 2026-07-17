from fastapi import FastAPI, Response, Cookie, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
import jwt
import uuid
from datetime import datetime, timedelta
import redis
import bcrypt
from pydantic import BaseModel, EmailStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# ENV 

class Settings(BaseSettings):
    database_url: str
    redis_host: str = "localhost"
    redis_port: int = 6379
    pepper:str 
    secret_key: str
    algorithm: str
    access_token_expire_minutes: int
    session_expire_days: int

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()

# --- DATABASE CONFIGURATION ---
engine = create_engine(
    settings.database_url, 
    connect_args={"connect_timeout": 5}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI()

# CORS CONFIGURATION
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# REDIS CONFIGURATION
try:
    redis_client = redis.Redis(
        host=settings.redis_host, 
        port=settings.redis_port, 
        db=0, 
        decode_responses=True,
        socket_timeout=3.0,
        socket_connect_timeout=3.0
        )
except Exception as e:
    print(f"Redis initialization warning: {e}")

# --- DATABASE MODEL ---
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="Senior_Developer")
    team_size = Column(Integer, default=8)
    completed_tasks = Column(Integer, default=142)
    performance_score = Column(Integer, default=98)

# Create tables in PostgreSQL (Local auto-migration)
Base.metadata.create_all(bind=engine)

# --- PYDANTIC SCHEMAS ---
class UserRegister(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

# Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- SECURITY UTILITIES (SALT & PEPPER INTEGRATION) ---

def hash_password(password: str) -> str:
    """
    Appends the secret PEPPER to the plain password,
    then hashes it with a unique, automatically generated bcrypt SALT.
    """
    # 1. Combine password with pepper
    peppered_password = password + settings.pepper
    
    # 2. Generate a unique salt and hash the combined string
    salt = bcrypt.gensalt(rounds=12) # 12 rounds is industry standard for work factor
    hashed = bcrypt.hashpw(peppered_password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Combines the input password with PEPPER and verifies it against
    the stored bcrypt hash (which contains the salt inside it).
    """
    peppered_password = plain_password + settings.pepper
    return bcrypt.checkpw(peppered_password.encode('utf-8'), hashed_password.encode('utf-8'))


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def create_redis_session(user_id: int, role: str) -> str:
    session_id = str(uuid.uuid4())
    session_data = {"user_id": str(user_id), "role": role}
    redis_client.hset(f"session:{session_id}", mapping=session_data)
    redis_client.expire(f"session:{session_id}", timedelta(days=settings.session_expire_days))
    return session_id


# --- API ENDPOINTS ---

@app.post("/api/auth/register")
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """Registers a new user using Salt + Pepper hashing."""
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered.")
    
    # Securely hash with Pepper + Salt
    hashed_pass = hash_password(user_data.password)
    
    new_user = User(
        email=user_data.email,
        hashed_password=hashed_pass
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully.", "email": new_user.email}


@app.post("/api/auth/login")
def login(user_data: UserLogin, response: Response, db: Session = Depends(get_db)):
    """Verifies user credentials using the Salt + Pepper verification logic."""
    db_user = db.query(User).filter(User.email == user_data.email).first()
    
    # Verification checks the combined password + PEPPER against the database hash
    if not db_user or not verify_password(user_data.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password."
        )

    session_id = create_redis_session(db_user.id, db_user.role)
    access_token = create_access_token({"user_id": db_user.id, "role": db_user.role})

    response.set_cookie(
        key="access_token", value=access_token, httponly=True, secure=False, samesite="lax"
    )
    response.set_cookie(
        key="session_id", value=session_id, httponly=True, secure=False, samesite="lax"
    )

    return {"message": "Login successful"}


@app.get("/api/dashboard")
def get_dashboard(access_token: str = Cookie(None), session_id: str = Cookie(None), db: Session = Depends(get_db)):
    if not access_token:
        raise HTTPException(status_code=401, detail="Access denied: Token missing")
        
    try:
        payload = jwt.decode(access_token, settings.secret_key, algorithms=[settings.algorithm])
        user_id = payload.get("user_id")
        
    except jwt.ExpiredSignatureError:
        if session_id and redis_client.exists(f"session:{session_id}"):
            session_data = redis_client.hgetall(f"session:{session_id}")
            user_id = session_data.get("user_id")
            db_user = db.query(User).filter(User.id == int(user_id)).first()
            if not db_user:
                raise HTTPException(status_code=401, detail="User not found")
                
            new_access_token = create_access_token({"user_id": db_user.id, "role": db_user.role})
            response.set_cookie(
                key="access_token", value=new_access_token, httponly=True, secure=False, samesite="lax", max_age=1800
            )
        else:
            raise HTTPException(status_code=401, detail="Session expired, please login again.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Return standard unified metrics for all verified users
    return {
        "user_id": user_id,
        "email": "synchronized_user@enterprise.com",
        "role": "Senior_Developer",
        "team_size": 8,
        "completed_tasks": 142,
        "performance_score": 98
    }


@app.post("/api/auth/logout")
def logout(response: Response, session_id: str = Cookie(None)):
    if session_id:
        redis_client.delete(f"session:{session_id}")
    response.delete_cookie("access_token")
    response.delete_cookie("session_id")
    return {"message": "Logout successful"}