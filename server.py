
import os
import json
import hmac
import hashlib
import time
from decimal import Decimal, InvalidOperation
from urllib.parse import parse_qsl

import httpx
from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import (
    create_engine, Column, Integer, BigInteger, String, Boolean,
    Text, Numeric, ForeignKey, DateTime, func
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session


# ============================================================
# BNB X GEMS - BACKEND
# ============================================================

APP_NAME = "BNB X GEMS"
ADMIN_ID = int(os.getenv("ADMIN_ID", "8251220398"))
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./bnb_x_gems.db")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine_options = {}
if DATABASE_URL.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_options)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

app = FastAPI(title=APP_NAME, version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DATABASE TABLES
# ============================================================

class User(Base):
    __tablename__ = "users"

    id = Column(BigInteger, primary_key=True)
    first_name = Column(String(150), default="")
    username = Column(String(150), nullable=True)
    wallet = Column(String(150), nullable=True)
    gems = Column(Numeric(24, 8), default=0)
    referred_by = Column(BigInteger, nullable=True)
    referral_paid = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=False)


class Channel(Base):
    __tablename__ = "channels"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(150), nullable=False)
    username = Column(String(150), nullable=False)
    invite_link = Column(String(500), nullable=True)
    enabled = Column(Boolean, default=True)


class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, default="")
    link = Column(String(1000), nullable=True)
    reward = Column(Numeric(24, 8), default=0)
    category = Column(String(80), default="General")
    enabled = Column(Boolean, default=True)
    verification = Column(String(40), default="admin")
    created_at = Column(DateTime, server_default=func.now())


class TaskClaim(Base):
    __tablename__ = "task_claims"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False)
    task_id = Column(Integer, nullable=False)
    status = Column(String(30), default="pending")
    created_at = Column(DateTime, server_default=func.now())


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False)
    kind = Column(String(50), nullable=False)
    amount = Column(Numeric(24, 8), nullable=False)
    note = Column(String(500), default="")
    created_at = Column(DateTime, server_default=func.now())


class Withdrawal(Base):
    __tablename__ = "withdrawals"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False)
    wallet = Column(String(150), nullable=False)
    bnb_amount = Column(Numeric(24, 8), nullable=False)
    gems_amount = Column(Numeric(24, 8), nullable=False)
    status = Column(String(30), default="pending")
    tx_hash = Column(String(250), nullable=True)
    admin_note = Column(String(500), default="")
    created_at = Column(DateTime, server_default=func.now())


Base.metadata.create_all(bind=engine)


# ============================================================
# DEFAULT SETTINGS
# ============================================================

DEFAULT_SETTINGS = {
    "welcome_bonus": "0",
    "referral_reward": "50",
    "daily_bonus": "0",
    "gems_per_usd": "10000",
    "min_withdraw_bnb": "0.1",
    "max_withdraw_bnb": "10",
    "bnb_usd_price": "0",
    "withdrawals_enabled": "true",
    "referrals_enabled": "true",
    "bot_username": "",
    "bot_name": "",
    "miniapp_short_name": "",
    "currency_name": "GEMS",
}


def setting(db: Session, key: str, fallback=None):
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        return row.value
    return fallback


def set_setting(db: Session, key: str, value):
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        row.value = str(value)
    else:
        db.add(Setting(key=key, value=str(value)))


def initialise_settings():
    db = SessionLocal()
    try:
        for key, value in DEFAULT_SETTINGS.items():
            if not db.query(Setting).filter(Setting.key == key).first():
                db.add(Setting(key=key, value=value))
        db.commit()
    finally:
        db.close()


initialise_settings()


# ============================================================
# DATABASE DEPENDENCY
# ============================================================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================
# TELEGRAM MINI APP AUTHENTICATION
# ============================================================

def validate_telegram_init_data(init_data: str):
    if not BOT_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="BOT_TOKEN is not configured on the backend."
        )

    if not init_data:
        raise HTTPException(status_code=401, detail="Telegram data is missing.")

    try:
        values = dict(parse_qsl(init_data, keep_blank_values=True))
        received_hash = values.pop("hash", None)

        if not received_hash:
            raise ValueError("Missing hash")

        data_check_string = "\n".join(
            f"{key}={value}" for key, value in sorted(values.items())
        )

        secret_key = hmac.new(
            b"WebAppData",
            BOT_TOKEN.encode("utf-8"),
            hashlib.sha256
        ).digest()

        calculated_hash = hmac.new(
            secret_key,
            data_check_string.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(calculated_hash, received_hash):
            raise ValueError("Invalid Telegram signature")

        auth_date = int(values.get("auth_date", "0"))
        if auth_date <= 0 or time.time() - auth_date > 86400:
            raise ValueError("Telegram login has expired")

        user_data = json.loads(values.get("user", "{}"))
        if not user_data.get("id"):
            raise ValueError("Telegram user ID missing")

        return user_data, values

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired Telegram login. Reopen the Mini App."
        )


def get_current_user(
    x_telegram_init_data: str = Header(default="", alias="X-Telegram-Init-Data"),
    db: Session = Depends(get_db)
):
    telegram_user, _ = validate_telegram_init_data(x_telegram_init_data)
    user_id = int(telegram_user["id"])

    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        user = User(
            id=user_id,
            first_name=telegram_user.get("first_name", ""),
            username=telegram_user.get("username"),
            gems=Decimal("0")
        )
        db.add(user)
        db.flush()

        welcome = Decimal(setting(db, "welcome_bonus", "0"))
        if welcome > 0:
            user.gems = welcome
            db.add(Transaction(
                user_id=user_id,
                kind="welcome_bonus",
                amount=welcome,
                note="Welcome bonus"
            ))

        db.commit()
        db.refresh(user)
    else:
        user.first_name = telegram_user.get("first_name", user.first_name)
        user.username = telegram_user.get("username", user.username)
        db.commit()

    return user


def require_admin(user: User):
    if int(user.id) != ADMIN_ID:
        raise HTTPException(status_code=403, detail="Admin access only.")
    return user


# ============================================================
# REQUEST MODELS
# ============================================================

class WalletInput(BaseModel):
    wallet: str = Field(min_length=42, max_length=42)


class ReferralInput(BaseModel):
    referrer_id: int


class WithdrawalInput(BaseModel):
    amount: Decimal


class TaskInput(BaseModel):
    title: str
    description: str = ""
    link: str = ""
    reward: Decimal = Decimal("0")
    category: str = "General"
    verification: str = "admin"
    enabled: bool = True


class ChannelInput(BaseModel):
    title: str
    username: str
    invite_link: str = ""
    enabled: bool = True


class AdminDecision(BaseModel):
    approved: bool
    note: str = ""
    tx_hash: str = ""


# ============================================================
# PUBLIC CONFIG
# ============================================================

@app.get("/")
def home():
    return {
        "app": APP_NAME,
        "status": "online",
        "message": "BNB X GEMS API is running."
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/config")
def get_config(db: Session = Depends(get_db)):
    keys = list(DEFAULT_SETTINGS.keys())
    data = {key: setting(db, key, DEFAULT_SETTINGS[key]) for key in keys}

    channels = db.query(Channel).filter(Channel.enabled == True).all()

    return {
        "app_name": APP_NAME,
        "bot_name": data["bot_name"],
        "bot_username": data["bot_username"],
        "miniapp_short_name": data["miniapp_short_name"],
        "currency_name": data["currency_name"],
        "channels": [
            {
                "id": c.id,
                "title": c.title,
                "username": c.username,
                "invite_link": c.invite_link
            }
            for c in channels
        ],
        "settings": {
            "welcome_bonus": data["welcome_bonus"],
            "referral_reward": data["referral_reward"],
            "daily_bonus": data["daily_bonus"],
            "gems_per_usd": data["gems_per_usd"],
            "min_withdraw_bnb": data["min_withdraw_bnb"],
            "max_withdraw_bnb": data["max_withdraw_bnb"],
            "bnb_usd_price": data["bnb_usd_price"],
            "withdrawals_enabled": data["withdrawals_enabled"] == "true",
            "referrals_enabled": data["referrals_enabled"] == "true"
        }
    }


# ============================================================
# AUTH / USER PROFILE
# ============================================================

@app.post("/auth/telegram")
def telegram_login(user: User = Depends(get_current_user)):
    return {
        "ok": True,
        "user": {
            "id": user.id,
            "first_name": user.first_name,
            "username": user.username,
            "gems": str(user.gems),
            "wallet": user.wallet
        }
    }


@app.get("/me")
def my_profile(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    referrals = db.query(User).filter(User.referred_by == user.id).count()
    transactions = db.query(Transaction).filter(
        Transaction.user_id == user.id
    ).count()

    return {
        "id": user.id,
        "first_name": user.first_name,
        "username": user.username,
        "gems": str(user.gems),
        "wallet": user.wallet,
        "referrals": referrals,
        "transactions": transactions
    }


@app.post("/wallet")
def save_wallet(
    data: WalletInput,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    wallet = data.wallet.strip()

    if not wallet.startswith("0x"):
        raise HTTPException(status_code=400, detail="Enter a valid BEP20 address.")

    try:
        int(wallet[2:], 16)
    except ValueError:
        raise HTTPException(status_code=400, detail="Wallet address is not valid.")

    user.wallet = wallet
    db.commit()
    return {"ok": True, "wallet": user.wallet}


# ============================================================
# REFERRALS
# Referral reward is paid after the invited user gets their
# first approved task, not just for opening a referral link.
# ============================================================

@app.post("/referrals/apply")
def apply_referral(
    data: ReferralInput,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if setting(db, "referrals_enabled", "true") != "true":
        raise HTTPException(status_code=400, detail="Referrals are disabled.")

    if data.referrer_id == user.id:
        raise HTTPException(status_code=400, detail="You cannot refer yourself.")

    if user.referred_by:
        raise HTTPException(status_code=400, detail="Referral already registered.")

    referrer = db.query(User).filter(User.id == data.referrer_id).first()
    if not referrer:
        raise HTTPException(status_code=404, detail="Referrer not found.")

    user.referred_by = referrer.id
    db.commit()

    return {
        "ok": True,
        "message": "Referral registered. Reward is pending qualification."
    }


# ============================================================
# TASKS
# ============================================================

@app.get("/tasks")
def list_tasks(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    tasks = db.query(Task).filter(Task.enabled == True).order_by(Task.id.desc()).all()

    result = []
    for task in tasks:
        claim = db.query(TaskClaim).filter(
            TaskClaim.user_id == user.id,
            TaskClaim.task_id == task.id
        ).first()

        result.append({
            "id": task.id,
            "title": task.title,
            "description": task.description,
            "link": task.link,
            "reward": str(task.reward),
            "category": task.category,
            "verification": task.verification,
            "status": claim.status if claim else "available"
        })

    return result


@app.post("/tasks/{task_id}/claim")
def claim_task(
    task_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    task = db.query(Task).filter(
        Task.id == task_id,
        Task.enabled == True
    ).first()

    if not task:
        raise HTTPException(status_code=404, detail="Task not found.")

    existing = db.query(TaskClaim).filter(
        TaskClaim.user_id == user.id,
        TaskClaim.task_id == task_id
    ).first()

    if existing:
        raise HTTPException(status_code=400, detail="You already submitted this task.")

    db.add(TaskClaim(
        user_id=user.id,
        task_id=task_id,
        status="pending"
    ))
    db.commit()

    return {"ok": True, "message": "Task submitted for verification."}


@app.get("/transactions")
def transaction_history(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    rows = db.query(Transaction).filter(
        Transaction.user_id == user.id
    ).order_by(Transaction.id.desc()).limit(100).all()

    return [
        {
            "id": row.id,
            "kind": row.kind,
            "amount": str(row.amount),
            "note": row.note,
            "created_at": str(row.created_at)
        }
        for row in rows
    ]


# ============================================================
# WITHDRAWALS
# Amount conversion uses the BNB/USD price configured by admin.
# A request only becomes paid after an admin records a confirmed
# transaction hash. This file does not pretend a payout happened.
# ============================================================

@app.post("/withdrawals")
def create_withdrawal(
    data: WithdrawalInput,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if setting(db, "withdrawals_enabled", "true") != "true":
        raise HTTPException(status_code=400, detail="Withdrawals are disabled.")

    if not user.wallet:
        raise HTTPException(status_code=400, detail="Set your BEP20 wallet first.")

    try:
        amount = Decimal(data.amount)
        minimum = Decimal(setting(db, "min_withdraw_bnb", "0.1"))
        maximum = Decimal(setting(db, "max_withdraw_bnb", "10"))
        price = Decimal(setting(db, "bnb_usd_price", "0"))
        gems_per_usd = Decimal(setting(db, "gems_per_usd", "10000"))
    except InvalidOperation:
        raise HTTPException(status_code=500, detail="Withdrawal settings are invalid.")

    if amount <= 0 or amount < minimum or amount > maximum:
        raise HTTPException(
            status_code=400,
            detail=f"Minimum is {minimum} BNB and maximum is {maximum} BNB."
        )

    if price <= 0:
        raise HTTPException(
            status_code=503,
            detail="BNB/USD price has not been configured by admin."
        )

    gems_needed = amount * price * gems_per_usd

    if Decimal(user.gems) < gems_needed:
        raise HTTPException(status_code=400, detail="Insufficient GEMS balance.")

    user.gems = Decimal(user.gems) - gems_needed

    withdrawal = Withdrawal(
        user_id=user.id,
        wallet=user.wallet,
        bnb_amount=amount,
        gems_amount=gems_needed,
        status="pending"
    )
    db.add(withdrawal)

    db.add(Transaction(
        user_id=user.id,
        kind="withdrawal_reserved",
        amount=-gems_needed,
        note=f"Withdrawal request #{withdrawal.id or 'new'}"
    ))

    db.commit()
    db.refresh(withdrawal)

    return {
        "ok": True,
        "withdrawal_id": withdrawal.id,
        "status": withdrawal.status,
        "bnb_amount": str(withdrawal.bnb_amount),
        "gems_reserved": str(withdrawal.gems_amount)
    }


@app.get("/withdrawals")
def my_withdrawals(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    rows = db.query(Withdrawal).filter(
        Withdrawal.user_id == user.id
    ).order_by(Withdrawal.id.desc()).all()

    return [
        {
            "id": row.id,
            "bnb_amount": str(row.bnb_amount),
            "gems_amount": str(row.gems_amount),
            "wallet": row.wallet,
            "status": row.status,
            "tx_hash": row.tx_hash,
            "created_at": str(row.created_at)
        }
        for row in rows
    ]


# ============================================================
# ADMIN AUTH HELPER
# ============================================================

def admin_user(user: User):
    require_admin(user)
    return user


# ============================================================
# ADMIN SETTINGS
# ============================================================

@app.get("/admin/settings")
def admin_get_settings(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    admin_user(user)
    rows = db.query(Setting).all()
    return {row.key: row.value for row in rows}


@app.post("/admin/settings")
def admin_update_settings(
    values: dict,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    admin_user(user)

    allowed = {
        "welcome_bonus",
        "referral_reward",
        "daily_bonus",
        "gems_per_usd"