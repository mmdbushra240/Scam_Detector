import io
import os
import uvicorn
import pytesseract

# Point directly to the installed Tesseract executable on Windows
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Form, File, UploadFile, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

# File parsing imports
import pdfplumber
from PIL import Image
import pytesseract

# Import detection engine
from scam_engine import ScamDetector

app = FastAPI(
    title="Internship & Job Scam Detector API",
    description="Async API to detect fake offer letters via text analysis and document OCR.",
    version="2.0.0"
)

# Initialize Scam Detector Engine
detector = ScamDetector(model_path="model.pkl")

# Jinja2 templates directory setup
templates = Jinja2Templates(directory="templates")


# --- Pydantic Request / Response Models ---
class ScamAnalysisRequest(BaseModel):
    job_text: str = Field(..., min_length=10, description="The job posting or offer letter text.")
    sender_email: Optional[str] = Field(default="", description="Recruiter or sender email address.")
    asks_money: bool = Field(default=False, description="Whether the offer requests payment or deposit fees.")


class ScamAnalysisResponse(BaseModel):
    risk_score: int = Field(..., ge=0, le=100)
    status: str
    flags: List[str]
    extracted_text_preview: Optional[str] = None


# --- Web Page Route ---
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

# --- JSON API Endpoint ---
@app.post("/api/analyze", response_model=ScamAnalysisResponse)
async def analyze_offer_json(payload: ScamAnalysisRequest):
    try:
        result = detector.evaluate_offer(
            text=payload.job_text,
            email=payload.sender_email,
            asks_for_money=payload.asks_money
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


# --- Form API Endpoint ---
@app.post("/analyze-form", response_model=ScamAnalysisResponse)
async def analyze_offer_form(
    job_text: str = Form(...),
    sender_email: Optional[str] = Form(""),
    asks_money: Optional[bool] = Form(False)
):
    result = detector.evaluate_offer(
        text=job_text,
        email=sender_email,
        asks_for_money=asks_money
    )
    return result


# --- OCR File Upload Endpoint (PDF & Image Processing) ---
@app.post("/api/analyze-file", response_model=ScamAnalysisResponse)
async def analyze_file(
    file: UploadFile = File(...),
    sender_email: Optional[str] = Form(""),
    asks_money: Optional[bool] = Form(False)
):
    extracted_text = ""
    filename = file.filename.lower()

    try:
        # 1. Process PDF Documents
        if filename.endswith(".pdf"):
            contents = await file.read()
            with pdfplumber.open(io.BytesIO(contents)) as pdf:
                for page in pdf.pages:
                    extracted_text += (page.extract_text() or "") + "\n"

        # 2. Process Image Documents (PNG, JPG, JPEG)
        elif filename.endswith((".png", ".jpg", ".jpeg")):
            contents = await file.read()
            image = Image.open(io.BytesIO(contents))
            extracted_text = pytesseract.image_to_string(image)

        else:
            raise HTTPException(status_code=400, detail="Unsupported file format. Upload a PDF or Image.")

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {str(e)}")

    if not extracted_text.strip():
        raise HTTPException(status_code=400, detail="Could not extract readable text from the uploaded file.")

    # 3. Evaluate Extracted Text
    result = detector.evaluate_offer(
        text=extracted_text,
        email=sender_email,
        asks_for_money=asks_money
    )
    result["extracted_text_preview"] = extracted_text[:200].strip() + "..."
    return result


if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)