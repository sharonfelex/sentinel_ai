from io import BytesIO

import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile

app = FastAPI(
    title="Sentinel AI API",
    description="Backend API for network intrusion detection and threat analysis.",
    version="0.2.0",
)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


@app.get("/", tags=["General"])
def root() -> dict[str, str]:
    """Return basic API information."""
    return {
        "application": "Sentinel AI",
        "message": "Network intrusion detection API",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
def health_check() -> dict[str, str]:
    """Health check used to verify that the API is running."""
    return {
        "status": "ok",
        "application": "Sentinel AI",
    }


@app.post("/upload-csv", tags=["Data Upload"])
async def upload_csv(file: UploadFile = File(...)):
    """
    Upload and validate a network traffic CSV file.
    Returns dataset metadata, not the uploaded traffic contents.
    """
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Only CSV files are accepted.",
        )

    contents = await file.read()

    if len(contents) == 0:
        raise HTTPException(
            status_code=400,
            detail="The uploaded file is empty.",
        )

    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File is too large. Maximum allowed size is 10 MB.",
        )

    try:
        df = pd.read_csv(BytesIO(contents))
    except (pd.errors.ParserError, UnicodeDecodeError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="Could not read the CSV. Check its format and encoding.",
        )

    if len(df.columns) == 0:
        raise HTTPException(
            status_code=400,
            detail="The CSV must contain column headers.",
        )

    columns = [str(column).strip() for column in df.columns]

    if any(not column for column in columns):
        raise HTTPException(
            status_code=400,
            detail="CSV column names cannot be empty.",
        )

    if len(columns) != len(set(columns)):
        raise HTTPException(
            status_code=400,
            detail="The CSV contains duplicate column names.",
        )

    if df.empty:
        raise HTTPException(
            status_code=400,
            detail="The CSV contains headers but no data rows.",
        )

    return {
        "status": "success",
        "filename": file.filename,
        "total_rows": int(len(df)),
        "total_columns": int(len(df.columns)),
        "columns": columns,
        "message": "CSV uploaded and validated successfully.",
    }
