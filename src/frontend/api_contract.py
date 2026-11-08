"""Typed models and shared rules for the Sentinel AI detection API.

This module mirrors ``docs/architecture/api-contract.md`` (contract v0.1).
If the contract changes, update both files in the same pull request.

The severity, confidence-band and label-mapping helpers are the reference
implementation of contract sections 3 and 7, so the backend, the ML pipeline
and the dashboard can all apply the same rules.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, model_validator

CONTRACT_VERSION = "0.1"

DetectionClass = Literal["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "Bot"]
Severity = Literal["None", "Low", "Medium", "High", "Critical"]
ConfidenceBand = Literal["strong", "moderate", "weak"]

DETECTION_CLASSES: tuple[str, ...] = get_args(DetectionClass)
SEVERITY_LEVELS: tuple[str, ...] = get_args(Severity)

# --- Contract section 7: severity and confidence rules ----------------------

CLASS_SEVERITY: dict[str, str] = {
    "BENIGN": "None",
    "PortScan": "Medium",
    "BruteForce": "High",
    "Bot": "High",
    "DoS": "High",
    "DDoS": "Critical",
}

STRONG_CONFIDENCE = 0.90
MODERATE_CONFIDENCE = 0.60


def severity_for(prediction: str, is_anomaly: bool = False) -> str:
    """Return the contract severity for a prediction.

    Severity depends only on the predicted class and the anomaly flag,
    never on model confidence.
    """
    if prediction not in CLASS_SEVERITY:
        raise ValueError(f"Unknown detection class: {prediction!r}")
    if prediction == "BENIGN":
        return "Low" if is_anomaly else "None"
    return CLASS_SEVERITY[prediction]


def confidence_band_for(confidence: float) -> str:
    """Map a model confidence in [0, 1] to its contract band."""
    if not 0.0 <= confidence <= 1.0:
        raise ValueError(f"Confidence must be between 0 and 1, got {confidence}")
    if confidence >= STRONG_CONFIDENCE:
        return "strong"
    if confidence >= MODERATE_CONFIDENCE:
        return "moderate"
    return "weak"


# --- Contract section 3: CICIDS2017 label mapping --------------------------

def _normalise_label(label: str) -> str:
    text = label.strip().lower()
    for separator in ("–", "—", "\x96", "�"):
        text = text.replace(separator, "-")
    return " ".join(text.split())


LABEL_TO_CLASS: dict[str, str] = {
    _normalise_label(original): mvp_class
    for original, mvp_class in {
        "BENIGN": "BENIGN",
        "DoS Hulk": "DoS",
        "DoS GoldenEye": "DoS",
        "DoS slowloris": "DoS",
        "DoS Slowhttptest": "DoS",
        "DDoS": "DDoS",
        "PortScan": "PortScan",
        "FTP-Patator": "BruteForce",
        "SSH-Patator": "BruteForce",
        "Bot": "Bot",
    }.items()
}

EXCLUDED_LABELS: frozenset[str] = frozenset(
    _normalise_label(label)
    for label in (
        "Heartbleed",
        "Infiltration",
        "Web Attack - Brute Force",
        "Web Attack - XSS",
        "Web Attack - Sql Injection",
    )
)


def map_label(label: str | None) -> str | None:
    """Map an original CICIDS2017 label to an MVP class.

    Returns ``None`` for labels excluded from the MVP and for unknown labels.
    Callers should log unknown labels (see ``is_known_label``) rather than
    mapping them to a class.
    """
    if label is None:
        return None
    return LABEL_TO_CLASS.get(_normalise_label(label))


def is_known_label(label: str) -> bool:
    """True if the label is either mapped or explicitly excluded."""
    key = _normalise_label(label)
    return key in LABEL_TO_CLASS or key in EXCLUDED_LABELS


# --- Contract section 6: response models ------------------------------------

class _ContractModel(BaseModel):
    # Unknown fields are ignored so additive backend changes never break the UI.
    model_config = ConfigDict(extra="ignore")


class HealthResponse(_ContractModel):
    status: str
    application: str
    mode: Literal["mock", "model"] | None = None
    model_loaded: bool | None = None

    @property
    def is_ok(self) -> bool:
        return self.status == "ok"


class UploadValidationResponse(_ContractModel):
    status: str
    filename: str
    total_rows: int = Field(ge=0)
    total_columns: int = Field(ge=0)
    columns: list[str]
    message: str
    missing_features: list[str] | None = None
    ready_for_detection: bool | None = None


class AnomalyResult(_ContractModel):
    is_anomaly: bool
    score: float | None = None
    method: str | None = None


class EvidenceItem(_ContractModel):
    feature: str
    value: float | None = None
    contribution: float | None = None


class FlowInfo(_ContractModel):
    flow_id: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: int | None = None
    timestamp: str | None = None


class DetectionResult(_ContractModel):
    row_index: int = Field(ge=0)
    prediction: DetectionClass
    is_malicious: bool
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_band: ConfidenceBand
    severity: Severity
    detection_method: str
    anomaly: AnomalyResult | None = None
    evidence: list[EvidenceItem] = Field(default_factory=list)
    flow: FlowInfo | None = None
    true_label: str | None = None
    true_class: DetectionClass | None = None

    @model_validator(mode="after")
    def _is_malicious_matches_prediction(self) -> "DetectionResult":
        if self.is_malicious != (self.prediction != "BENIGN"):
            raise ValueError(
                "is_malicious must be true exactly when prediction is not BENIGN"
            )
        return self

    @property
    def is_anomaly(self) -> bool:
        return bool(self.anomaly and self.anomaly.is_anomaly)

    @property
    def needs_review(self) -> bool:
        """Weak-confidence attack predictions are shown as needing review."""
        return self.is_malicious and self.confidence_band == "weak"


class RowError(_ContractModel):
    row_index: int = Field(ge=0)
    column: str | None = None
    message: str


class DetectionSummary(_ContractModel):
    total_rows: int = Field(ge=0)
    analyzed_rows: int = Field(ge=0)
    skipped_rows: int = Field(ge=0)
    benign_count: int = Field(ge=0)
    malicious_count: int = Field(ge=0)
    anomaly_count: int = Field(ge=0)
    by_class: dict[DetectionClass, int]
    by_severity: dict[Severity, int]

    @model_validator(mode="after")
    def _counts_are_consistent(self) -> "DetectionSummary":
        problems = []
        if self.analyzed_rows + self.skipped_rows != self.total_rows:
            problems.append("analyzed_rows + skipped_rows must equal total_rows")
        if self.benign_count + self.malicious_count != self.analyzed_rows:
            problems.append("benign_count + malicious_count must equal analyzed_rows")
        if sum(self.by_class.values()) != self.analyzed_rows:
            problems.append("by_class counts must add up to analyzed_rows")
        if sum(self.by_severity.values()) != self.analyzed_rows:
            problems.append("by_severity counts must add up to analyzed_rows")
        if self.by_class.get("BENIGN", 0) != self.benign_count:
            problems.append("by_class['BENIGN'] must equal benign_count")
        if problems:
            raise ValueError("; ".join(problems))
        return self


class DetectionBatchResponse(_ContractModel):
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
    def _results_match_summary(self) -> "DetectionBatchResponse":
        if len(self.results) != self.summary.analyzed_rows:
            raise ValueError("results must contain one entry per analyzed row")
        return self

    @property
    def alerts(self) -> list[DetectionResult]:
        """Rows the dashboard should show as alerts: attacks and anomalies."""
        return [r for r in self.results if r.is_malicious or r.is_anomaly]


class ModelInfo(_ContractModel):
    contract_version: str
    model_version: str
    detection_method: str
    is_mock: bool
    classes: list[DetectionClass]
    features: list[str]
    anomaly_method: str | None = None
    trained_on: str | None = None
    metrics: dict[str, Any] | None = None


def build_summary(
    results: Iterable[DetectionResult], *, total_rows: int
) -> DetectionSummary:
    """Build a contract-consistent summary from per-row results."""
    results = list(results)
    by_class = {name: 0 for name in DETECTION_CLASSES}
    by_severity = {level: 0 for level in SEVERITY_LEVELS}
    for result in results:
        by_class[result.prediction] += 1
        by_severity[result.severity] += 1
    malicious = sum(1 for r in results if r.is_malicious)
    return DetectionSummary(
        total_rows=total_rows,
        analyzed_rows=len(results),
        skipped_rows=total_rows - len(results),
        benign_count=len(results) - malicious,
        malicious_count=malicious,
        anomaly_count=sum(1 for r in results if r.is_anomaly),
        by_class=by_class,
        by_severity=by_severity,
    )
