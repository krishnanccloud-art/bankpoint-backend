from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import uuid
import os

# Firebase Init
cred_path = "/etc/secrets/serviceAccountKey.json" if os.path.exists("/etc/secrets/serviceAccountKey.json") else "serviceAccountKey.json"
cred = credentials.Certificate(cred_path)
firebase_admin.initialize_app(cred)
db = firestore.client()

app = FastAPI(title="BankPoint API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

SECRET_KEY = "bankpoint-super-secret-key-2024"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class AccountCreate(BaseModel):
    account_type: str

class TransactionCreate(BaseModel):
    to_account: str
    amount: float
    description: Optional[str] = ""

def hash_password(password): return pwd_context.hash(password)
def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)

def create_token(data):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if not user_id: raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Token expired or invalid")

def generate_account_number(): return "BP" + str(uuid.uuid4().int)[:10]

@app.get("/")
def root(): return {"message": "Welcome to BankPoint API 🏦", "status": "running"}

@app.post("/auth/register", status_code=201)
def register(user: UserRegister):
    users_ref = db.collection("users")
    if users_ref.where("email", "==", user.email).get():
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = str(uuid.uuid4())
    users_ref.document(user_id).set({"user_id": user_id, "name": user.name, "email": user.email, "phone": user.phone, "password": hash_password(user.password), "created_at": datetime.utcnow().isoformat()})
    return {"message": "Registration successful", "token": create_token({"user_id": user_id, "email": user.email}), "user_id": user_id}

@app.post("/auth/login")
def login(user: UserLogin):
    docs = db.collection("users").where("email", "==", user.email).get()
    if not docs: raise HTTPException(status_code=401, detail="Invalid email or password")
    user_doc = docs[0].to_dict()
    if not verify_password(user.password, user_doc["password"]): raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"message": "Login successful", "token": create_token({"user_id": user_doc["user_id"], "email": user_doc["email"]}), "user": {"name": user_doc["name"], "email": user_doc["email"]}}

@app.get("/users/me")
def get_profile(user_id: str = Depends(get_current_user)):
    doc = db.collection("users").document(user_id).get()
    if not doc.exists: raise HTTPException(status_code=404, detail="User not found")
    data = doc.to_dict(); data.pop("password", None); return data

@app.post("/accounts", status_code=201)
def create_account(account: AccountCreate, user_id: str = Depends(get_current_user)):
    account_id = str(uuid.uuid4())
    account_data = {"account_id": account_id, "user_id": user_id, "account_number": generate_account_number(), "account_type": account.account_type, "balance": 0.0, "created_at": datetime.utcnow().isoformat()}
    db.collection("accounts").document(account_id).set(account_data)
    return {"message": "Account created", "account": account_data}

@app.get("/accounts")
def get_accounts(user_id: str = Depends(get_current_user)):
    return {"accounts": [d.to_dict() for d in db.collection("accounts").where("user_id", "==", user_id).get()]}

@app.get("/accounts/{account_id}/balance")
def get_balance(account_id: str, user_id: str = Depends(get_current_user)):
    doc = db.collection("accounts").document(account_id).get()
    if not doc.exists: raise HTTPException(status_code=404, detail="Account not found")
    data = doc.to_dict()
    if data["user_id"] != user_id: raise HTTPException(status_code=403, detail="Unauthorized")
    return {"account_number": data["account_number"], "balance": data["balance"]}

@app.post("/transactions", status_code=201)
def send_money(txn: TransactionCreate, user_id: str = Depends(get_current_user)):
    sender_docs = db.collection("accounts").where("user_id", "==", user_id).get()
    if not sender_docs: raise HTTPException(status_code=404, detail="Sender account not found")
    sender_ref = db.collection("accounts").document(sender_docs[0].id)
    sender = sender_ref.get().to_dict()
    if sender["balance"] < txn.amount: raise HTTPException(status_code=400, detail="Insufficient balance")
    receiver_docs = db.collection("accounts").where("account_number", "==", txn.to_account).get()
    if not receiver_docs: raise HTTPException(status_code=404, detail="Receiver account not found")
    receiver_ref = db.collection("accounts").document(receiver_docs[0].id)
    receiver = receiver_ref.get().to_dict()
    sender_ref.update({"balance": sender["balance"] - txn.amount})
    receiver_ref.update({"balance": receiver["balance"] + txn.amount})
    txn_id = str(uuid.uuid4())
    txn_data = {"txn_id": txn_id, "from_user": user_id, "from_account": sender["account_number"], "to_account": txn.to_account, "amount": txn.amount, "description": txn.description, "status": "success", "timestamp": datetime.utcnow().isoformat()}
    db.collection("transactions").document(txn_id).set(txn_data)
    return {"message": "Transaction successful", "transaction": txn_data}

@app.get("/transactions")
def get_transactions(user_id: str = Depends(get_current_user)):
    return {"transactions": [d.to_dict() for d in db.collection("transactions").where("from_user", "==", user_id).get()]}