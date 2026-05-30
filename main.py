import os
import jwt
import bcrypt
import pymongo
from pymongo import MongoClient
import httpx
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from dotenv import load_dotenv
import asyncio

load_dotenv()

# MongoDB config
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "casino_db")
MONGO_COLLECTION_USERS = os.getenv("MONGO_COLLECTION_USERS", "users")

# Telo config
TELO_API_BASE = os.getenv("TELO_API_BASE", "https://api.telo.is/api/v2")
AGENT_CODE = os.getenv("AGENT_CODE", "jumpapegas880")
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "4c7995b7856a5b0377149d48a47fd4b1")

# JWT
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

app = FastAPI()

# Koneksi sync (pymongo)
client = MongoClient(MONGO_URI)
db = client[MONGO_DB_NAME]
users_collection = db[MONGO_COLLECTION_USERS]

# Async wrapper untuk operasi blocking
async def find_one(collection, filter):
    return await asyncio.to_thread(collection.find_one, filter)

async def insert_one(collection, document):
    return await asyncio.to_thread(collection.insert_one, document)

# Models
class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class AmountRequest(BaseModel):
    amount: int

# JWT helpers
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

security = HTTPBearer()
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(401, "Invalid token")
        return username
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid token")

# Telo API caller
async def call_telo_api(endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    url = f"{TELO_API_BASE}/{endpoint}"
    async with httpx.AsyncClient(timeout=20.0) as http_client:
        response = await http_client.post(url, json=payload, headers={"Content-Type": "application/json"})
        if response.status_code != 200:
            return {"status": 0, "msg": "TELO_API_HTTP_ERROR", "detail": response.text}
        return response.json()

# Endpoints
@app.post("/register")
async def register(request: RegisterRequest):
    user_code = request.username.strip()
    existing = await find_one(users_collection, {"user_code": user_code})
    if existing:
        return {"status": 0, "msg": "USER_EXISTS"}

    telo_payload = {"agent_code": AGENT_CODE, "agent_token": AGENT_TOKEN, "user_code": user_code}
    telo_resp = await call_telo_api("user_create", telo_payload)
    if telo_resp.get("status") != 1 and telo_resp.get("msg") != "DUPLICATED_USER":
        return telo_resp

    hashed = bcrypt.hashpw(request.password.encode('utf-8'), bcrypt.gensalt())
    await insert_one(users_collection, {"user_code": user_code, "password_hash": hashed.decode('utf-8')})
    return {"status": 1, "msg": "REGISTER_SUCCESS"}

@app.post("/login")
async def login(request: LoginRequest):
    user = await find_one(users_collection, {"user_code": request.username.strip()})
    if not user:
        return {"status": 0, "msg": "USER_NOT_FOUND"}
    if not bcrypt.checkpw(request.password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        return {"status": 0, "msg": "WRONG_PASSWORD"}
    token = create_access_token(data={"sub": user['user_code']})
    return {"status": 1, "msg": "LOGIN_SUCCESS", "token": token}

@app.get("/info")
async def get_info(current_user: str = Depends(get_current_user)):
    payload = {"agent_code": AGENT_CODE, "agent_token": AGENT_TOKEN, "user_code": current_user}
    telo_resp = await call_telo_api("info", payload)
    if telo_resp.get("status") != 1:
        return {"status": 0, "msg": "TELO_API_ERROR"}
    balance = 0
    for user in telo_resp.get("user_list", []):
        if user.get("user_code") == current_user:
            balance = int(user.get("user_balance", 0))
            break
    return {"status": 1, "balance": balance}

@app.post("/deposit")
async def deposit(request: AmountRequest, current_user: str = Depends(get_current_user)):
    if request.amount <= 0:
        return {"status": 0, "msg": "INVALID_AMOUNT"}
    user = await find_one(users_collection, {"user_code": current_user})
    if not user:
        return {"status": 0, "msg": "USER_NOT_FOUND"}
    payload = {"agent_code": AGENT_CODE, "agent_token": AGENT_TOKEN, "user_code": current_user, "amount": request.amount}
    return await call_telo_api("user_deposit", payload)

@app.post("/withdraw")
async def withdraw(request: AmountRequest, current_user: str = Depends(get_current_user)):
    if request.amount <= 0:
        return {"status": 0, "msg": "INVALID_AMOUNT"}
    user = await find_one(users_collection, {"user_code": current_user})
    if not user:
        return {"status": 0, "msg": "USER_NOT_FOUND"}
    payload = {"agent_code": AGENT_CODE, "agent_token": AGENT_TOKEN, "user_code": current_user, "amount": request.amount}
    return await call_telo_api("user_withdraw", payload)

@app.get("/game-list")
async def game_list(provider: str = Query(...)):
    if not provider:
        return {"status": 0, "msg": "PROVIDER_REQUIRED"}
    payload = {"agent_code": AGENT_CODE, "agent_token": AGENT_TOKEN, "provider_code": provider, "lang": "en"}
    resp = await call_telo_api("game_list", payload)
    if not isinstance(resp, dict) or resp.get("status") != 1 or "games" not in resp:
        return {"status": 0, "msg": "FAILED_LOAD_GAME", "raw": resp}
    return {"status": 1, "games": resp["games"]}

@app.get("/game-launch", response_class=RedirectResponse)
async def game_launch(provider: str = Query(...), game: str = Query(...), current_user: str = Depends(get_current_user)):
    if not provider or not game:
        raise HTTPException(400, "INVALID_PARAM")
    payload = {"agent_code": AGENT_CODE, "agent_token": AGENT_TOKEN, "user_code": current_user, "game_type": "slot", "provider_code": provider, "game_code": game, "lang": "en"}
    resp = await call_telo_api("game_launch", payload)
    if resp.get("status") == 1 and resp.get("launch_url"):
        return RedirectResponse(url=resp["launch_url"])
    raise HTTPException(500, "FAILED_LAUNCH")