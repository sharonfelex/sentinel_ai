from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
import uuid

import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, Field, model_validator

app = FastAPI(title="Sentinel AI API", description="Network intrusion detection API.", version="0.2.0")

MAX_FILE_SIZE = 10 * 1024 * 1024
CONTRACT_VERSION = "0.1"
CLASSES = ("BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "Bot")
SEVERITIES = ("None", "Low", "Medium", "High", "Critical")


class AnomalyResult(BaseModel):
    is_anomaly: bool
    score: float | None = None
    method: str | None = None


class FlowInfo(BaseModel):
    flow_id: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: int | None = None
    timestamp: str | None = None


class DetectionResult(BaseModel):
    row_index: int = Field(ge=0)
    prediction: str
    is_malicious: bool
    confidence: float = Field(ge=0, le=1)
    confidence_band: str
    severity: str
    detection_method: str
    anomaly: AnomalyResult | None = None
    evidence: list[dict] = Field(default_factory=list)
    flow: FlowInfo | None = None
    true_label: str | None = None
    true_class: str | None = None

    @model_validator(mode="after")
    def validate_contract(self):
        if self.prediction not in CLASSES:
            raise ValueError("prediction must be one of the six MVP classes")
        if self.is_malicious != (self.prediction != "BENIGN"):
            raise ValueError("is_malicious must match prediction")
        if self.severity not in SEVERITIES:
            raise ValueError("invalid severity")
        if self.confidence_band not in {"strong", "moderate", "weak"}:
            raise ValueError("invalid confidence band")
        return self


class RowError(BaseModel):
    row_index: int = Field(ge=0)
    column: str | None = None
    message: str


class DetectionSummary(BaseModel):
    total_rows: int = Field(ge=0)
    analyzed_rows: int = Field(ge=0)
    skipped_rows: int = Field(ge=0)
    benign_count: int = Field(ge=0)
    malicious_count: int = Field(ge=0)
    anomaly_count: int = Field(ge=0)
    by_class: dict[str, int]
    by_severity: dict[str, int]

    @model_validator(mode="after")
    def validate_counts(self):
        if self.analyzed_rows + self.skipped_rows != self.total_rows:
            raise ValueError("analyzed_rows + skipped_rows must equal total_rows")
        if self.benign_count + self.malicious_count != self.analyzed_rows:
            raise ValueError("benign_count + malicious_count must equal analyzed_rows")
        if sum(self.by_class.values()) != self.analyzed_rows:
            raise ValueError("by_class counts must equal analyzed_rows")
        if sum(self.by_severity.values()) != self.analyzed_rows:
            raise ValueError("by_severity counts must equal analyzed_rows")
        if self.by_class.get("BENIGN", 0) != self.benign_count:
            raise ValueError("by_class BENIGN must equal benign_count")
        return self


class DetectionBatchResponse(BaseModel):
    contract_version: str
    request_id: str
    filename: str
    processed_at: datetime
    is_mock: bool
    model_version: str
    detection_method: str
    summary: DetectionSummary
    results: list[DetectionResult]
    row_errors: list[RowError] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_results(self):
        if len(self.results) != self.summary.analyzed_rows:
            raise ValueError("results must contain one entry per analyzed row")
        return self


class ModelInfo(BaseModel):
    contract_version: str
    model_version: str
    detection_method: str
    is_mock: bool
    classes: list[str]
    features: list[str]
    anomaly_method: str | None = None
    trained_on: str | None = None
    metrics: dict | None = None


class UploadResponse(BaseModel):
    status: str
    filename: str
    total_rows: int
    total_columns: int
    columns: list[str]
    message: str
    missing_features: list[str] | None = None
    ready_for_detection: bool | None = None


def _confidence_band(confidence: float) -> str:
    return "strong" if confidence >= 0.90 else "moderate" if confidence >= 0.60 else "weak"


def _severity(prediction: str, anomaly: bool) -> str:
    if prediction == "BENIGN":
        return "Low" if anomaly else "None"
    return {"PortScan": "Medium", "BruteForce": "High", "Bot": "High", "DoS": "High", "DDoS": "Critical"}[prediction]


def _map_label(label: str | None) -> str | None:
    if label is None:
        return None
    key = " ".join(label.strip().lower().replace("–", "-").replace("—", "-").split())
    return {
        "benign": "BENIGN",
        "dos hulk": "DoS",
        "dos goldeneye": "DoS",
        "dos slowloris": "DoS",
        "dos slowhttptest": "DoS",
        "ddos": "DDoS",
        "portscan": "PortScan",
        "ftp-patator": "BruteForce",
        "ssh-patator": "BruteForce",
        "bot": "Bot",
    }.get(key)


def _read_csv(contents: bytes) -> pd.DataFrame:
    try:
        return pd.read_csv(BytesIO(contents), index_col=False)
    except UnicodeDecodeError:
        try:
            return pd.read_csv(BytesIO(contents), encoding="cp1252", index_col=False)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Could not read the CSV. Check its format and encoding.") from exc
    except (pd.errors.ParserError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Could not read the CSV. Check its format and encoding.") from exc


async def _validate_upload(file: UploadFile) -> pd.DataFrame:
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are accepted.")
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File is too large. Maximum allowed size is 10 MB.")

    df = _read_csv(contents)
    columns = [str(column).strip() for column in df.columns]
    if not columns:
        raise HTTPException(status_code=400, detail="The CSV must contain column headers.")
    if any(not column or column.startswith("Unnamed:") for column in columns):
        raise HTTPException(status_code=400, detail="CSV column names cannot be empty.")
    if len(columns) != len(set(columns)):
        raise HTTPException(status_code=400, detail="The CSV contains duplicate column names.")
    if df.empty:
        raise HTTPException(status_code=400, detail="The CSV contains headers but no data rows.")
    df.columns = columns
    return df


def _mock_detection(df: pd.DataFrame, filename: str) -> DetectionBatchResponse:
    results: list[DetectionResult] = []
    row_errors: list[RowError] = []
    for idx, row in df.iterrows():
        try:
            label = str(row["Label"]).strip() if "Label" in df.columns and pd.notna(row["Label"]) else None
            true_class = _map_label(label)
            prediction = true_class or "BENIGN"
            confidence = 0.99 if true_class else 0.70
            anomaly = prediction == "BENIGN" and int(idx) % 5 == 4
            flow_values = {}
            for column, field in {
                "Flow ID": "flow_id", "Source IP": "source_ip", "Destination IP": "destination_ip",
                "Timestamp": "timestamp",
            }.items():
                if column in df.columns and pd.notna(row[column]):
                    flow_values[field] = str(row[column])
            for column, field in {
                "Source Port": "source_port", "Destination Port": "destination_port", "Protocol": "protocol"
            }.items():
                if column in df.columns and pd.notna(row[column]):
                    flow_values[field] = int(float(row[column]))
            results.append(DetectionResult(
                row_index=int(idx), prediction=prediction, is_malicious=prediction != "BENIGN",
                confidence=confidence, confidence_band=_confidence_band(confidence),
                severity=_severity(prediction, anomaly), detection_method="Mock",
                anomaly=AnomalyResult(is_anomaly=anomaly, score=0.8 if anomaly else 0.1, method="Mock"),
                evidence=[], flow=FlowInfo(**flow_values) if flow_values else None,
                true_label=label, true_class=true_class,
            ))
        except (TypeError, ValueError, OverflowError) as exc:
            row_errors.append(RowError(row_index=int(idx), message=str(exc)))

    by_class = {name: 0 for name in CLASSES}
    by_severity = {name: 0 for name in SEVERITIES}
    for result in results:
        by_class[result.prediction] += 1
        by_severity[result.severity] += 1
    malicious = sum(r.is_malicious for r in results)
    summary = DetectionSummary(
        total_rows=len(df), analyzed_rows=len(results), skipped_rows=len(df) - len(results),
        benign_count=len(results) - malicious, malicious_count=malicious,
        anomaly_count=sum(bool(r.anomaly and r.anomaly.is_anomaly) for r in results),
        by_class=by_class, by_severity=by_severity,
    )
    return DetectionBatchResponse(
        contract_version=CONTRACT_VERSION, request_id=str(uuid.uuid4()),
        filename=filename, processed_at=datetime.now(timezone.utc),
        is_mock=True, model_version="mock", detection_method="Mock",
        summary=summary, results=results, row_errors=row_errors[:100],
    )


@app.get("/", tags=["General"])
def root() -> dict[str, str]:
    return {"application": "Sentinel AI", "message": "Network intrusion detection API", "docs": "/docs"}


@app.get("/health", tags=["Health"])
def health_check() -> dict:
    return {"status": "ok", "application": "Sentinel AI", "mode": "mock", "model_loaded": False}


@app.post("/upload-csv", response_model=UploadResponse, tags=["Data Upload"])
async def upload_csv(file: UploadFile = File(...)) -> UploadResponse:
    df = await _validate_upload(file)
    return UploadResponse(
        status="success", filename=file.filename or "upload.csv",
        total_rows=len(df), total_columns=len(df.columns),
        columns=[str(c) for c in df.columns],
        message="CSV uploaded and validated successfully.", ready_for_detection=True,
    )


@app.post("/detect", response_model=DetectionBatchResponse, tags=["Detection"])
async def detect(file: UploadFile = File(...)) -> DetectionBatchResponse:
    df = await _validate_upload(file)
    return _mock_detection(df, file.filename or "upload.csv")


@app.get("/model/info", response_model=ModelInfo, tags=["Model"])
def model_info() -> ModelInfo:
    return ModelInfo(
        contract_version=CONTRACT_VERSION, model_version="mock",
        detection_method="Mock", is_mock=True, classes=list(CLASSES),
        features=[], anomaly_method="Mock", trained_on=None, metrics=None,
    )
