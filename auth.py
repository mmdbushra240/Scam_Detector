from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import Request, HTTPException, status

# Secret key for signing JWT tokens (Change this to a random string in production)
SECRET_KEY = "your-super-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # Token valid for 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Hash plain text password
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


# Verify plain text password against stored hash
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# Create JWT access token
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# Dependency to fetch current user from HTTP cookie
def get_current_user_from_cookie(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        # Remove 'Bearer ' prefix if present
        if token.startswith("Bearer "):
            token = token[7:]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return username
    except JWTError:
        return None