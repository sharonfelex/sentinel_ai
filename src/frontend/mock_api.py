"""Offline mock of the Sentinel AI API, for building the dashboard without a backend.

Every response has the same shape as the real API, and every detection
response is marked ``is_mock=True``. The predictions are random (but
repeatable for the same file) and are **not** real detections.

File validation follows the backend's ``POST /upload-csv`` rules, so invalid
uploads fail here the same way they would against the real API.
"""

from __future__ import annotations

import csv
import hashlib
import io
import math
import random
import uuid
from datetime import datetime, timezone

from src.frontend.api_client import ApiRequestError
from src.frontend.api_contract import (
    CONTRACT_VERSION,
    DETECTION_CLASSES,
    AnomalyResult,
    DetectionBatchResponse,
    DetectionResult,
    EvidenceItem,
    FlowInfo,
    HealthResponse,
    ModelInfo,
    UploadValidationResponse,
    build_summary,
    confidence_band_for,
    map_label,
    severity_for,
)

MAX_FILE_SIZE = 10 * 1024 * 1024  # matches the backend (contract section 9)
MOCK_METHOD = "Mock"
MOCK_MODEL_VERSION = "mock"

# Mostly benign traffic, like a real capture.
_CLASS_WEIGHTS = {
    "BENIGN": 0.80,
    "DoS": 0.06,
    "DDoS": 0.05,
    "PortScan": 0.05,
    "BruteForce": 0.02,
    "Bot": 0.02,
}
_ANOMALY_RATE = 0.05

_FLOW_COLUMNS = {
    "Flow ID": "flow_id",
    "Source IP": "source_ip",
    "Source Port": "source_port",
    "Destination IP": "destination_ip",
    "Destination Port": "destination_port",
    "Protocol": "protocol",
    "Timestamp": "timestamp",
}
_INTEGER_FLOW_FIELDS = {"source_port", "destination_port", "protocol"}


class MockSentinelApi:
    """Drop-in replacement for ``SentinelApiClient`` that never makes HTTP calls."""

    is_mock = True
    base_url = "mock://sentinel-api"

    def health(self) -> HealthResponse:
        return HealthResponse(
            status="ok", application="Sentinel AI (mock)", mode="mock", model_loaded=False
        )

    def validate_csv(self, filename: str, content: bytes) -> UploadValidationResponse:
        columns, rows = _read_csv(filename, content)
        return UploadValidationResponse(
            status="success",
            filename=filename,
            total_rows=len(rows),
            total_columns=len(columns),
            columns=columns,
            message="CSV uploaded and validated successfully (mock API).",
        )

    def detect_csv(self, filename: str, content: bytes) -> DetectionBatchResponse:
        columns, rows = _read_csv(filename, content)
        rng = random.Random(hashlib.sha256(content).hexdigest())
        results = [
            _mock_result(index, dict(zip(columns, row)), rng)
            for index, row in enumerate(rows)
        ]
        return DetectionBatchResponse(
            contract_version=CONTRACT_VERSION,
            request_id=str(uuid.uuid4()),
            filename=filename,
            processed_at=datetime.now(timezone.utc),
            is_mock=True,
            model_version=MOCK_MODEL_VERSION,
            detection_method=MOCK_METHOD,
            summary=build_summary(results, total_rows=len(rows)),
            results=results,
            row_errors=[],
        )

    def model_info(self) -> ModelInfo:
        return ModelInfo(
            contract_version=CONTRACT_VERSION,
            model_version=MOCK_MODEL_VERSION,
            detection_method=MOCK_METHOD,
            is_mock=True,
            classes=list(DETECTION_CLASSES),
            features=[],
            anomaly_method=MOCK_METHOD,
            trained_on=None,
            metrics=None,
        )

    def close(self) -> None:
        """Nothing to close; present so the mock matches the live client."""


def _read_csv(filename: str, content: bytes) -> tuple[list[str], list[list[str]]]:
    """Validate an upload the way ``POST /upload-csv`` does and return its table."""
    if not filename or not filename.lower().endswith(".csv"):
        raise ApiRequestError("Only CSV files are accepted.", status_code=400)
    if len(content) == 0:
        raise ApiRequestError("The uploaded file is empty.", status_code=400)
    if len(content) > MAX_FILE_SIZE:
        raise ApiRequestError(
            "File is too large. Maximum allowed size is 10 MB.", status_code=413
        )

    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        # Some CICIDS2017 files contain cp1252 bytes in their labels
        # (contract section 12 recommends the same fallback for the backend).
        text = content.decode("cp1252", errors="replace")

    try:
        records = [row for row in csv.reader(io.StringIO(text)) if any(c.strip() for c in row)]
    except csv.Error as exc:
        raise ApiRequestError(
            "Could not read the CSV. Check its format and encoding.", status_code=400
        ) from exc

    if not records:
        raise ApiRequestError("The CSV must contain column headers.", status_code=400)

    columns = [name.strip() for name in _mangle_duplicates(records[0])]
    if any(not name for name in columns):
        raise ApiRequestError("CSV column names cannot be empty.", status_code=400)
    if len(columns) != len(set(columns)):
        raise ApiRequestError("The CSV contains duplicate column names.", status_code=400)

    rows = records[1:]
    if not rows:
        raise ApiRequestError("The CSV contains headers but no data rows.", status_code=400)
    if any(len(row) > len(columns) for row in rows):
        raise ApiRequestError(
            "Could not read the CSV. Check its format and encoding.", status_code=400
        )
    return columns, rows


def _mangle_duplicates(header: list[str]) -> list[str]:
    """Rename exact duplicate headers to ``name.1``, ``name.2`` as pandas does."""
    seen: dict[str, int] = {}
    names = []
    for name in header:
        if name in seen:
            seen[name] += 1
            names.append(f"{name}.{seen[name]}")
        else:
            seen[name] = 0
            names.append(name)
    return names


def _mock_result(index: int, row: dict[str, str], rng: random.Random) -> DetectionResult:
    prediction = rng.choices(list(_CLASS_WEIGHTS), weights=list(_CLASS_WEIGHTS.values()))[0]
    confidence = round(rng.uniform(0.55, 0.99), 3)
    is_anomaly = rng.random() < _ANOMALY_RATE
    anomaly_score = round(rng.uniform(0.6, 1.0) if is_anomaly else rng.uniform(0.0, 0.5), 3)
    true_label = row.get("Label")
    true_label = true_label.strip() if true_label is not None else None

    return DetectionResult(
        row_index=index,
        prediction=prediction,
        is_malicious=prediction != "BENIGN",
        confidence=confidence,
        confidence_band=confidence_band_for(confidence),
        severity=severity_for(prediction, is_anomaly),
        detection_method=MOCK_METHOD,
        anomaly=AnomalyResult(is_anomaly=is_anomaly, score=anomaly_score, method=MOCK_METHOD),
        evidence=_mock_evidence(row, rng) if prediction != "BENIGN" else [],
        flow=_flow_info(row),
        true_label=true_label,
        true_class=map_label(true_label),
    )


def _mock_evidence(row: dict[str, str], rng: random.Random) -> list[EvidenceItem]:
    numeric = []
    for name, raw in row.items():
        if name == "Label" or name in _FLOW_COLUMNS:
            continue
        try:
            value = float(raw)
        except (TypeError, ValueError):
            continue
        if math.isfinite(value):
            numeric.append((name, value))
    chosen = rng.sample(numeric, k=min(3, len(numeric)))
    return [
        EvidenceItem(feature=name, value=value, contribution=round(rng.uniform(0.05, 0.3), 3))
        for name, value in chosen
    ]


def _flow_info(row: dict[str, str]) -> FlowInfo | None:
    values: dict[str, object] = {}
    for column, field in _FLOW_COLUMNS.items():
        raw = (row.get(column) or "").strip()
        if not raw:
            continue
        if field in _INTEGER_FLOW_FIELDS:
            try:
                values[field] = int(float(raw))
            except ValueError:
                continue
        else:
            values[field] = raw
    return FlowInfo(**values) if values else None
