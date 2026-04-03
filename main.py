from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import uuid
import os

# ─── Firebase Init ───────────────────────────────────────────
import json
cred_dict = json.loads(os.environ.get("FIREBASE_CREDENTIALS"))
cred = credentials.Certificate(cred_dict)
firebase_admin.initialize_app(cred)
db = firestore.client()

# ─── App Init ────────────────────────────────────────────────
app = FastAPI(title="BankPoint API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── JWT Config ──────────────────────────────────────────────
SECRET_KEY = "bankpoint-super-secret-key-2024"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# ─── Pydantic Models ─────────────────────────────────────────
class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class AccountCreate(BaseModel):
    account_type: str  # savings / current

class TransactionCreate(BaseModel):
    to_account: str
    amount: float
    description: Optional[str] = ""

# ─── Helper Functions ────────────────────────────────────────
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_token(data: dict) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Token expired or invalid")

def generate_account_number() -> str:
    return "BP" + str(uuid.uuid4().int)[:10]

# ─── Routes ──────────────────────────────────────────────────

@app.get("/")
def root():
    return {"message": "Welcome to BankPoint API 🏦", "status": "running"}

# ── Auth ──
@app.post("/auth/register", status_code=201)
def register(user: UserRegister):
    users_ref = db.collection("users")

    # Check duplicate email
    existing = users_ref.where("email", "==", user.email).get()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_id = str(uuid.uuid4())
    user_data = {
        "user_id": user_id,
        "name": user.name,
        "email": user.email,
        "phone": user.phone,
        "password": hash_password(user.password),
        "created_at": datetime.utcnow().isoformat()
    }
    users_ref.document(user_id).set(user_data)
    token = create_token({"user_id": user_id, "email": user.email})
    return {"message": "Registration successful", "token": token, "user_id": user_id}

@app.post("/auth/login")
def login(user: UserLogin):
    users_ref = db.collection("users")
    docs = users_ref.where("email", "==", user.email).get()

    if not docs:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user_doc = docs[0].to_dict()
    if not verify_password(user.password, user_doc["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_token({"user_id": user_doc["user_id"], "email": user_doc["email"]})
    return {
        "message": "Login successful",
        "token": token,
        "user": {"name": user_doc["name"], "email": user_doc["email"]}
    }

# ── Users ──
@app.get("/users/me")
def get_profile(user_id: str = Depends(get_current_user)):
    doc = db.collection("users").document(user_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="User not found")
    data = doc.to_dict()
    data.pop("password", None)
    return data

# ── Accounts ──
@app.post("/accounts", status_code=201)
def create_account(account: AccountCreate, user_id: str = Depends(get_current_user)):
    account_id = str(uuid.uuid4())
    account_data = {
        "account_id": account_id,
        "user_id": user_id,
        "account_number": generate_account_number(),
        "account_type": account.account_type,
        "balance": 0.0,
        "created_at": datetime.utcnow().isoformat()
    }
    db.collection("accounts").document(account_id).set(account_data)
    return {"message": "Account created", "account": account_data}

@app.get("/accounts")
def get_accounts(user_id: str = Depends(get_current_user)):
    docs = db.collection("accounts").where("user_id", "==", user_id).get()
    return {"accounts": [d.to_dict() for d in docs]}

@app.get("/accounts/{account_id}/balance")
def get_balance(account_id: str, user_id: str = Depends(get_current_user)):
    doc = db.collection("accounts").document(account_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Account not found")
    data = doc.to_dict()
    if data["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Unauthorized")
    return {"account_number": data["account_number"], "balance": data["balance"]}

# ── Transactions ──
@app.post("/transactions", status_code=201)
def send_money(txn: TransactionCreate, user_id: str = Depends(get_current_user)):
    # Get sender's account
    sender_docs = db.collection("accounts").where("user_id", "==", user_id).get()
    if not sender_docs:
        raise HTTPException(status_code=404, detail="Sender account not found")
    sender_ref = db.collection("accounts").document(sender_docs[0].id)
    sender = sender_ref.get().to_dict()

    if sender["balance"] < txn.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    # Get receiver's account
    receiver_docs = db.collection("accounts").where("account_number", "==", txn.to_account).get()
    if not receiver_docs:
        raise HTTPException(status_code=404, detail="Receiver account not found")
    receiver_ref = db.collection("accounts").document(receiver_docs[0].id)
    receiver = receiver_ref.get().to_dict()

    # Update balances
    sender_ref.update({"balance": sender["balance"] - txn.amount})
    receiver_ref.update({"balance": receiver["balance"] + txn.amount})

    # Record transaction
    txn_id = str(uuid.uuid4())
    txn_data = {
        "txn_id": txn_id,
        "from_user": user_id,
        "from_account": sender["account_number"],
        "to_account": txn.to_account,
        "amount": txn.amount,
        "description": txn.description,
        "status": "success",
        "timestamp": datetime.utcnow().isoformat()
    }
    db.collection("transactions").document(txn_id).set(txn_data)
    return {"message": "Transaction successful", "transaction": txn_data}

@app.get("/transactions")
def get_transactions(user_id: str = Depends(get_current_user)):
    docs = db.collection("transactions").where("from_user", "==", user_id).get()
    return {"transactions": [d.to_dict() for d in docs]}

