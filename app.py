from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import database, auth

# Initialize Database Tables
database.init_db()

app = FastAPI()

# Mount templates directory
templates = Jinja2Templates(directory="templates")

# --- AUTH ROUTES ---

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(request=request, name="register.html")

@app.post("/register")
def register_user(
    username: str = Form(...), 
    email: str = Form(...), 
    password: str = Form(...), 
    db: Session = Depends(database.get_db)
):
    # Check if user already exists
    existing_user = db.query(database.User).filter(
        (database.User.username == username) | (database.User.email == email)
    ).first()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    # Create new user record
    hashed_pw = auth.get_password_hash(password)
    new_user = database.User(username=username, email=email, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html")

@app.post("/login")
def login_user(
    response: Response,
    username: str = Form(...), 
    password: str = Form(...), 
    db: Session = Depends(database.get_db)
):
    user = db.query(database.User).filter(database.User.username == username).first()
    
    if not user or not auth.verify_password(password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    
    # Create JWT Token and set HTTP-only cookie
    access_token = auth.create_access_token(data={"sub": user.username})
    redirect_res = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    redirect_res.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    return redirect_res

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("access_token")
    return response

# --- DASHBOARD / MAIN ROUTE ---

@app.get("/", response_class=HTMLResponse)
def home_page(request: Request):
    current_user = auth.get_current_user_from_cookie(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    return templates.TemplateResponse(
        request=request, 
        name="index.html", 
        context={"user": current_user}
    )