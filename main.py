import os
import jwt
import bcrypt
import motor.motor_asyncio
import httpx
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables dari .env (hanya untuk lokal)
load_dotenv()

# ===============================
# KONFIGURASI MONGODB (dari env)
# ===============================
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "casino_db")
MONGO_COLLECTION_USERS = os.getenv("MONGO_COLLECTION_USERS", "users")

# ===============================
# KONFIGURASI TELO (dari env)
# ===============================
TELO_API_BASE = os.getenv("TELO_API_BASE", "https://api.telo.is/api/v2")
AGENT_CODE = os.getenv("AGENT_CODE", "jumpapegas880")
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "4c7995b7856a5b0377149d48a47fd4b1")

# ===============================
# KONFIGURASI JWT (dari env)
# ===============================
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

app = FastAPI(title="Casino API (MongoDB)", description="API untuk integrasi Telo dengan MongoDB")

# ===============================
# MODEL PYDANTIC
# ===============================
class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class AmountRequest(BaseModel):
    amount: int

# ===============================
# KONEKSI MONGODB (ASYNC)
# ===============================
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = client[MONGO_DB_NAME]
users_collection = db[MONGO_COLLECTION_USERS]

# ===============================
# JWT AUTHENTIKASI
# ===============================
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ===============================
# HELPER PANGGIL TELO API
# ===============================
async def call_telo_api(endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Melakukan panggilan POST ke API Telo"""
    url = f"{TELO_API_BASE}/{endpoint}"
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        if response.status_code != 200:
            return {"status": 0, "msg": "TELO_API_HTTP_ERROR", "detail": response.text}
        return response.json()

# ===============================
# ENDPOINTS (sama seperti sebelumnya)
# ===============================

@app.post("/register", response_model=Dict[str, Any])
async def register(request: RegisterRequest):
    user_code = request.username.strip()
    password = request.password

    existing = await users_collection.find_one({"user_code": user_code})
    if existing:
        return {"status": 0, "msg": "USER_EXISTS"}

    telo_payload = {
        "agent_code": AGENT_CODE,
        "agent_token": AGENT_TOKEN,
        "user_code": user_code
    }
    telo_resp = await call_telo_api("user_create", telo_payload)
    if telo_resp.get("status") != 1 and telo_resp.get("msg") != "DUPLICATED_USER":
        return telo_resp

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    await users_collection.insert_one({
        "user_code": user_code,
        "password_hash": hashed.decode('utf-8')
    })
    return {"status": 1, "msg": "REGISTER_SUCCESS"}

@app.post("/login", response_model=Dict[str, Any])
async def login(request: LoginRequest):
    username = request.username.strip()
    password = request.password

    user = await users_collection.find_one({"user_code": username})
    if not user:
        return {"status": 0, "msg": "USER_NOT_FOUND"}

    stored_hash = user['password_hash'].encode('utf-8')
    if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):
        return {"status": 0, "msg": "WRONG_PASSWORD"}

    token = create_access_token(data={"sub": user['user_code']})
    return {"status": 1, "msg": "LOGIN_SUCCESS", "token": token}

@app.get("/info", response_model=Dict[str, Any])
async def get_info(current_user: str = Depends(get_current_user)):
    payload = {
        "agent_code": AGENT_CODE,
        "agent_token": AGENT_TOKEN,
        "user_code": current_user
    }
    telo_resp = await call_telo_api("info", payload)
    if telo_resp.get("status") != 1:
        return {"status": 0, "msg": "TELO_API_ERROR"}

    balance = 0
    user_list = telo_resp.get("user_list", [])
    for user in user_list:
        if user.get("user_code") == current_user:
            balance = int(user.get("user_balance", 0))
            break
    return {"status": 1, "balance": balance}

@app.post("/deposit", response_model=Dict[str, Any])
async def deposit(request: AmountRequest, current_user: str = Depends(get_current_user)):
    amount = request.amount
    if amount <= 0:
        return {"status": 0, "msg": "INVALID_AMOUNT"}

    user = await users_collection.find_one({"user_code": current_user})
    if not user:
        return {"status": 0, "msg": "USER_NOT_FOUND"}

    payload = {
        "agent_code": AGENT_CODE,
        "agent_token": AGENT_TOKEN,
        "user_code": current_user,
        "amount": amount
    }
    resp = await call_telo_api("user_deposit", payload)
    return resp

@app.post("/withdraw", response_model=Dict[str, Any])
async def withdraw(request: AmountRequest, current_user: str = Depends(get_current_user)):
    amount = request.amount
    if amount <= 0:
        return {"status": 0, "msg": "INVALID_AMOUNT"}

    user = await users_collection.find_one({"user_code": current_user})
    if not user:
        return {"status": 0, "msg": "USER_NOT_FOUND"}

    payload = {
        "agent_code": AGENT_CODE,
        "agent_token": AGENT_TOKEN,
        "user_code": current_user,
        "amount": amount
    }
    resp = await call_telo_api("user_withdraw", payload)
    return resp

@app.get("/game-list", response_model=Dict[str, Any])
async def game_list(provider: str = Query(..., description="Provider code, e.g. 'pgsoft', 'jili'")):
    if not provider:
        return {"status": 0, "msg": "PROVIDER_REQUIRED"}

    payload = {
        "agent_code": AGENT_CODE,
        "agent_token": AGENT_TOKEN,
        "provider_code": provider,
        "lang": "en"
    }
    resp = await call_telo_api("game_list", payload)
    if not isinstance(resp, dict):
        return {"status": 0, "msg": "INVALID_TELO_RESPONSE"}
    if resp.get("status") != 1 or "games" not in resp:
        return {"status": 0, "msg": "FAILED_LOAD_GAME", "raw": resp}
    return {"status": 1, "games": resp["games"]}

@app.get("/game-launch", response_class=RedirectResponse)
async def game_launch(
    provider: str = Query(..., description="Provider code"),
    game: str = Query(..., description="Game code"),
    current_user: str = Depends(get_current_user)
):
    if not provider or not game:
        raise HTTPException(status_code=400, detail="INVALID_PARAM")

    payload = {
        "agent_code": AGENT_CODE,
        "agent_token": AGENT_TOKEN,
        "user_code": current_user,
        "game_type": "slot",
        "provider_code": provider,
        "game_code": game,
        "lang": "en"
    }
    resp = await call_telo_api("game_launch", payload)
    if resp.get("status") == 1 and resp.get("launch_url"):
        return RedirectResponse(url=resp["launch_url"])
    else:
        raise HTTPException(status_code=500, detail="FAILED_LAUNCH")

# ===============================
# UNTUK RUN LOKAL (bukan Vercel)
# ===============================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)