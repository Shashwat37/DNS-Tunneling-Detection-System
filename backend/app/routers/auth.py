from fastapi import APIRouter, HTTPException, status
from passlib.context import CryptContext
from bson import ObjectId

from app.db import get_db
from app.models import RegisterRequest, LoginRequest, TokenResponse
from app.dependencies import create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _hash_password(password: str) -> str:
    return pwd_context.hash(password)


def _verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest):
    """Create a new user account."""
    db = get_db()

    # Prevent duplicate emails (case-insensitive)
    existing = await db.users.find_one({"email": body.email.lower()})
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    doc = {
        "name": body.name.strip(),
        "email": body.email.lower(),
        "hashed_password": _hash_password(body.password),
    }
    result = await db.users.insert_one(doc)

    return {
        "message": "Account created successfully",
        "user_id": str(result.inserted_id),
    }


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest):
    """Authenticate and return a JWT."""
    db = get_db()

    user = await db.users.find_one({"email": body.email.lower()})
    if not user or not _verify_password(body.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    token = create_access_token(
        subject=str(user["_id"]),
        extra={"name": user["name"], "email": user["email"]},
    )

    return TokenResponse(
        access_token=token,
        user_name=user["name"],
        user_email=user["email"],
    )
