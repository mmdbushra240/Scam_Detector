FROM python:3.10-slim

# Install system dependencies (Tesseract OCR, libpq for PostgreSQL, gcc/build-essential)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    libpq-dev \
    gcc \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory inside container
WORKDIR /app

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy rest of the application code
COPY . .

# Expose FastAPI port
EXPOSE 10000

# Start command for Uvicorn on Render
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "10000"]