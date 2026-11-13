"""Display rules for the Streamlit dashboard, kept free of Streamlit imports.

Everything here turns contract models (``api_contract.py``) into the text and
tables the dashboard shows, so the wording rules from contract sections 7, 8
and 10 live in one tested place:

* confidence is shown as "Model confidence 0.72", never as attack probability;
* weak attack predictions are labelled "Needs analyst review";
* an anomaly on a benign row is an "Anomaly — unconfirmed" alert, not a class;
* mock results always carry the "Mock data — not live detection" label.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable

from src.frontend.api_contract import (
    SEVERITY_LEVELS,
    DetectionBatchResponse,
    DetectionResult,
)

MOCK_BANNER = "Mock data — not live detection"
ANOMALY_LABEL = "Anomaly — unconfirmed"
NEEDS_REVIEW_LABEL = "Needs analyst review"

_SEVERITY_ICON = {
    "None": "🟢",
    "Low": "🟡",
    "Medium": "🟠",
    "High": "🔴",
    "Critical": "🚨",
}
_SEVERITY_RANK = {level: rank for rank, level in enumerate(SEVERITY_LEVELS)}

FLOW_FIELDS = {
    "protocol": "Protocol",
    "destination_port": "Destination port",
    "source_ip": "Source IP",
    "destination_ip": "Destination IP",
}


def severity_label(severity: str) -> str:
    return f"{_SEVERITY_ICON.get(severity, '⚪')} {severity}"


def confidence_text(result: DetectionResult) -> str:
    """Contract 7.2: confidence is model confidence, not attack probability."""
    return f"Model confidence {result.confidence:.2f} ({result.confidence_band})"


def anomaly_text(result: DetectionResult) -> str:
    """Contract 8: ``anomaly: null`` (not run) differs from ``is_anomaly: false``."""
    if result.anomaly is None:
        return "Not run"
    return ANOMALY_LABEL if result.anomaly.is_anomaly else "No"


def is_anomaly_only(result: DetectionResult) -> bool:
    """A benign prediction flagged only by the anomaly detector."""
    return result.is_anomaly and not result.is_malicious


def alert_title(result: DetectionResult) -> str:
    """Headline for an alert card; anomaly-only alerts never show a class."""
    if is_anomaly_only(result):
        return f"{ANOMALY_LABEL} · row {result.row_index}"
    return f"{result.prediction} · row {result.row_index}"


def alert_status(result: DetectionResult) -> str:
    if is_anomaly_only(result):
        return "Unconfirmed — review traffic"
    if result.needs_review:
        return NEEDS_REVIEW_LABEL
    return "Classifier alert"


def sort_alerts(alerts: Iterable[DetectionResult]) -> list[DetectionResult]:
    """Most severe first, then by row order. Confidence does not affect order."""
    return sorted(
        alerts,
        key=lambda r: (-_SEVERITY_RANK.get(r.severity, -1), r.row_index),
    )


def classifier_alerts(batch: DetectionBatchResponse) -> list[DetectionResult]:
    return sort_alerts(r for r in batch.results if r.is_malicious)


def anomaly_alerts(batch: DetectionBatchResponse) -> list[DetectionResult]:
    return sort_alerts(r for r in batch.results if is_anomaly_only(r))


def result_rows(results: Iterable[DetectionResult]) -> list[dict[str, Any]]:
    """Table rows with confidence, severity and anomaly in separate columns."""
    return [
        {
            "Row": r.row_index,
            "Prediction": r.prediction,
            "Malicious": "Yes" if r.is_malicious else "No",
            "Model confidence": round(r.confidence, 3),
            "Confidence band": r.confidence_band,
            "Severity": severity_label(r.severity),
            "Anomaly": anomaly_text(r),
            "Status": alert_status(r) if (r.is_malicious or r.is_anomaly) else "",
            "Source IP": r.flow.source_ip if r.flow else None,
            "Destination": _destination(r),
            "Dataset label": r.true_label,
        }
        for r in results
    ]


def filter_results(
    results: Iterable[DetectionResult],
    *,
    classes: Iterable[str] | None = None,
    severities: Iterable[str] | None = None,
    alerts_only: bool = False,
) -> list[DetectionResult]:
    class_set = set(classes) if classes is not None else None
    severity_set = set(severities) if severities is not None else None
    return [
        r
        for r in results
        if (class_set is None or r.prediction in class_set)
        and (severity_set is None or r.severity in severity_set)
        and (not alerts_only or r.is_malicious or r.is_anomaly)
    ]


def flow_breakdown(
    results: Iterable[DetectionResult], field: str, *, top: int = 10
) -> list[dict[str, Any]]:
    """Count analysed flows by a ``FlowInfo`` field, split into benign/malicious."""
    total: Counter = Counter()
    malicious: Counter = Counter()
    for r in results:
        value = getattr(r.flow, field, None) if r.flow else None
        if value is None:
            continue
        total[value] += 1
        if r.is_malicious:
            malicious[value] += 1
    return [
        {
            FLOW_FIELDS.get(field, field): str(value),
            "Flows": count,
            "Malicious": malicious[value],
        }
        for value, count in total.most_common(top)
    ]


def dataset_agreement(results: Iterable[DetectionResult]) -> dict[str, int] | None:
    """Compare predictions with the CSV's own ``Label`` column, if it had one."""
    labelled = [r for r in results if r.true_label is not None]
    if not labelled:
        return None
    comparable = [r for r in labelled if r.true_class is not None]
    return {
        "labelled_rows": len(labelled),
        "comparable_rows": len(comparable),
        "matching_rows": sum(1 for r in comparable if r.prediction == r.true_class),
        "excluded_or_unknown": len(labelled) - len(comparable),
    }


def run_record(batch: DetectionBatchResponse) -> dict[str, Any]:
    """One line of the session's detection-run history."""
    summary = batch.summary
    return {
        "Processed (UTC)": batch.processed_at.strftime("%Y-%m-%d %H:%M:%S"),
        "File": batch.filename,
        "Source": MOCK_BANNER if batch.is_mock else f"Live · {batch.model_version}",
        "Rows": summary.total_rows,
        "Malicious": summary.malicious_count,
        "Anomalies": summary.anomaly_count,
        "Skipped": summary.skipped_rows,
        "Request ID": batch.request_id,
    }


def _destination(result: DetectionResult) -> str | None:
    flow = result.flow
    if not flow or not flow.destination_ip:
        return None
    if flow.destination_port is None:
        return flow.destination_ip
    return f"{flow.destination_ip}:{flow.destination_port}"


# --- Sample incident history ------------------------------------------------
# Contract section 1: GET /incidents is Phase 2. Until it exists, the incident
# history page shows these fixed demonstration records, always labelled as such.


@dataclass(frozen=True)
class SampleIncident:
    incident_id: str
    opened_at: str
    prediction: str
    severity: str
    source_ip: str
    target: str
    status: str
    summary: str


SAMPLE_INCIDENTS: tuple[SampleIncident, ...] = (
    SampleIncident(
        "DEMO-0006", "2026-11-07 14:22", "DDoS", "Critical",
        "multiple (34 hosts)", "192.168.10.50:80", "Contained",
        "Burst of short HTTP flows from many sources against the web server.",
    ),
    SampleIncident(
        "DEMO-0005", "2026-11-07 09:41", "BruteForce", "High",
        "205.174.165.73", "192.168.10.50:22", "Investigating",
        "Repeated SSH authentication attempts at a steady rate.",
    ),
    SampleIncident(
        "DEMO-0004", "2026-11-06 18:05", "BENIGN", "Low",
        "192.168.10.12", "192.168.10.3:53", "Closed — false positive",
        f"{ANOMALY_LABEL}: unusual DNS flow volume; reviewed as a backup job.",
    ),
    SampleIncident(
        "DEMO-0003", "2026-11-06 11:30", "PortScan", "Medium",
        "205.174.165.73", "192.168.10.0/24", "Closed",
        "Sequential connection attempts across many destination ports.",
    ),
    SampleIncident(
        "DEMO-0002", "2026-11-05 16:12", "Bot", "High",
        "192.168.10.15", "205.174.165.73:8080", "Closed",
        "Periodic beaconing from an internal host to an external address.",
    ),
    SampleIncident(
        "DEMO-0001", "2026-11-05 08:03", "DoS", "High",
        "205.174.165.73", "192.168.10.50:80", "Closed",
        "Slow HTTP connections held open against the web server.",
    ),
)


def sample_incident_rows() -> list[dict[str, Any]]:
    return [
        {
            "Incident": i.incident_id,
            "Opened": i.opened_at,
            "Classification": ANOMALY_LABEL if i.prediction == "BENIGN" else i.prediction,
            "Severity": severity_label(i.severity),
            "Source": i.source_ip,
            "Target": i.target,
            "Status": i.status,
            "Summary": i.summary,
        }
        for i in SAMPLE_INCIDENTS
    ]
