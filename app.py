from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Response, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session
import database, auth

# Initialize Database Tables
database.init_db()

app = FastAPI()

# Mount templates directory
templates = Jinja2Templates(directory="templates")


# Request schema matching frontend fetch payload
class AnalyzeRequest(BaseModel):
    job_text: str = ""
    sender_email: str = ""
    asks_money: bool = False


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
    existing_user = db.query(database.User).filter(
        (database.User.username == username) | (database.User.email == email)
    ).first()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
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
    
    access_token = auth.create_access_token(data={"sub": user.username})
    redirect_res = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    redirect_res.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    return redirect_res

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("access_token")
    return response


# --- DASHBOARD ROUTE ---

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


# --- ANALYSIS ENDPOINTS ---

@app.post("/api/analyze")
def analyze_text(payload: AnalyzeRequest):
    score = 0
    flags = []
    
    if payload.asks_money:
        score += 50
        flags.append("Requests upfront money, training fee, or deposit.")
        
    if payload.sender_email and any(free in payload.sender_email.lower() for free in ["gmail.com", "yahoo.com", "hotmail.com"]):
        score += 20
        flags.append("Recruiter using a free public domain email address instead of a corporate domain.")

    if "wire transfer" in payload.job_text.lower() or "crypto" in payload.job_text.lower():
        score += 30
        flags.append("Mentions suspicious payment methods (crypto/wire transfer).")

    verdict = "High Risk / Likely Scam" if score >= 60 else ("Moderate Risk" if score >= 30 else "Low Risk / Appears Safe")
    
    return {
        "risk_score": min(score, 100),
        "verdict": verdict,
        "flags": flags
    }

@app.post("/api/analyze-file")
async def analyze_file(
    file: UploadFile = File(...),
    sender_email: str = Form(""),
    asks_money: bool = Form(False)
):
    # Basic file analysis placeholder
    score = 40 if asks_money else 10
    flags = ["File uploaded successfully for scanning."]
    if asks_money:
        flags.append("Requests upfront money/deposit.")
        
    return {
        "risk_score": score,
        "verdict": "Moderate Risk" if score >= 30 else "Low Risk",
        "flags": flags,
        "extracted_text_preview": f"File '{file.filename}' processed successfully."
    }