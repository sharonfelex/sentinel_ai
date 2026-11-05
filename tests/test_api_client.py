"""Tests for the frontend API client, the offline mock and the contract rules."""

import json

import httpx
import pytest

from src.frontend.api_client import (
    ApiRequestError,
    ApiServerError,
    ApiUnavailableError,
    ContractError,
    SentinelApiClient,
    get_client,
)
from src.frontend.api_contract import (
    DETECTION_CLASSES,
    DetectionBatchResponse,
    DetectionResult,
    build_summary,
    confidence_band_for,
    is_known_label,
    map_label,
    severity_for,
)
from src.frontend.mock_api import MockSentinelApi

SAMPLE_CSV = (
    b" Destination Port, Flow Duration, Fwd Header Length, Fwd Header Length, Label\n"
    b"80,1200,40,40,BENIGN\n"
    b"443,3500,20,20,DDoS\n"
    b"22,90,32,32,SSH-Patator\n"
)

UPLOAD_OK = {
    "status": "success",
    "filename": "flows.csv",
    "total_rows": 3,
    "total_columns": 5,
    "columns": ["Destination Port", "Flow Duration", "Label"],
    "message": "CSV uploaded and validated successfully.",
}


def make_client(handler) -> SentinelApiClient:
    """A live client whose HTTP calls are answered by ``handler``."""
    http = httpx.Client(base_url="http://test", transport=httpx.MockTransport(handler))
    return SentinelApiClient(base_url="http://test", http_client=http)


def result(prediction="BENIGN", confidence=0.95, anomaly=False, index=0) -> DetectionResult:
    return DetectionResult(
        row_index=index,
        prediction=prediction,
        is_malicious=prediction != "BENIGN",
        confidence=confidence,
        confidence_band=confidence_band_for(confidence),
        severity=severity_for(prediction, anomaly),
        detection_method="Random Forest",
        anomaly={"is_anomaly": anomaly, "score": 0.5, "method": "Isolation Forest"},
    )


def batch_payload(results: list[DetectionResult], total_rows: int | None = None) -> dict:
    total = len(results) if total_rows is None else total_rows
    return {
        "contract_version": "0.1",
        "request_id": "6f1c2b9e-3d4a-4f7b-9c1e-2a5b8d7e0f13",
        "filename": "flows.csv",
        "processed_at": "2026-11-06T10:15:00Z",
        "is_mock": False,
        "model_version": "rf-baseline-0.1",
        "detection_method": "Random Forest",
        "summary": build_summary(results, total_rows=total).model_dump(mode="json"),
        "results": [r.model_dump(mode="json") for r in results],
        "row_errors": [],
    }


# --- Live client: success paths -------------------------------------------

def test_health_parses_current_backend_response():
    client = make_client(lambda request: httpx.Response(200, json={"status": "ok", "application": "Sentinel AI"}))
    health = client.health()
    assert health.is_ok
    assert health.mode is None  # optional field, not sent by PR #6 yet


def test_validate_csv_sends_multipart_file_field():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = request.read()
        seen["content_type"] = request.headers["content-type"]
        return httpx.Response(200, json=UPLOAD_OK)

    response = make_client(handler).validate_csv("flows.csv", SAMPLE_CSV)

    assert seen["path"] == "/upload-csv"
    assert seen["content_type"].startswith("multipart/form-data")
    assert b'name="file"; filename="flows.csv"' in seen["body"]
    assert SAMPLE_CSV in seen["body"]
    assert response.total_rows == 3


def test_detect_csv_parses_contract_response():
    results = [result("BENIGN"), result("DDoS", 0.96, index=1), result("BENIGN", 0.7, anomaly=True, index=3)]
    payload = batch_payload(results, total_rows=4)
    payload["row_errors"] = [{"row_index": 2, "column": "Flow Duration", "message": "not numeric"}]
    client = make_client(lambda request: httpx.Response(200, json=payload))

    batch = client.detect_csv("flows.csv", SAMPLE_CSV)

    assert batch.summary.malicious_count == 1
    assert batch.summary.skipped_rows == 1
    assert [r.row_index for r in batch.alerts] == [1, 3]


def test_unknown_response_fields_are_ignored():
    body = {"status": "ok", "application": "Sentinel AI", "uptime_seconds": 12}
    assert make_client(lambda request: httpx.Response(200, json=body)).health().is_ok


# --- Live client: error paths ----------------------------------------------

def test_backend_400_detail_string_becomes_message():
    client = make_client(lambda request: httpx.Response(400, json={"detail": "Only CSV files are accepted."}))
    with pytest.raises(ApiRequestError) as excinfo:
        client.validate_csv("flows.txt", b"x")
    assert str(excinfo.value) == "Only CSV files are accepted."
    assert excinfo.value.status_code == 400


def test_fastapi_422_detail_list_becomes_readable_message():
    detail = [{"loc": ["body", "file"], "msg": "Field required", "type": "missing"}]
    client = make_client(lambda request: httpx.Response(422, json={"detail": detail}))
    with pytest.raises(ApiRequestError, match="file: Field required"):
        client.validate_csv("flows.csv", SAMPLE_CSV)


def test_missing_endpoint_is_reported_clearly():
    client = make_client(lambda request: httpx.Response(404, json={"detail": "Not Found"}))
    with pytest.raises(ApiRequestError, match="/detect is not available"):
        client.detect_csv("flows.csv", SAMPLE_CSV)


def test_server_error_raises_api_server_error():
    client = make_client(lambda request: httpx.Response(500, text="Internal Server Error"))
    with pytest.raises(ApiServerError) as excinfo:
        client.health()
    assert excinfo.value.status_code == 500


@pytest.mark.parametrize(
    "error",
    [httpx.ConnectError("refused"), httpx.ReadTimeout("slow")],
    ids=["connection-refused", "timeout"],
)
def test_unreachable_backend_raises_unavailable(error):
    def handler(request):
        raise error

    with pytest.raises(ApiUnavailableError, match="http://test"):
        make_client(handler).health()


def test_non_json_response_is_contract_error():
    client = make_client(lambda request: httpx.Response(200, text="<html>proxy page</html>"))
    with pytest.raises(ContractError, match="not valid JSON"):
        client.health()


def test_missing_fields_are_contract_error():
    client = make_client(lambda request: httpx.Response(200, json={"status": "success"}))
    with pytest.raises(ContractError, match="does not match the API contract"):
        client.validate_csv("flows.csv", SAMPLE_CSV)


def test_inconsistent_is_malicious_is_contract_error():
    payload = batch_payload([result("DDoS", 0.96)])
    payload["results"][0]["is_malicious"] = False
    client = make_client(lambda request: httpx.Response(200, json=payload))
    with pytest.raises(ContractError):
        client.detect_csv("flows.csv", SAMPLE_CSV)


def test_summary_that_does_not_add_up_is_contract_error():
    payload = batch_payload([result("BENIGN"), result("DoS", index=1)])
    payload["summary"]["malicious_count"] = 2
    client = make_client(lambda request: httpx.Response(200, json=payload))
    with pytest.raises(ContractError):
        client.detect_csv("flows.csv", SAMPLE_CSV)


# --- get_client --------------------------------------------------------------

def test_get_client_defaults_to_live(monkeypatch):
    monkeypatch.delenv("SENTINEL_API_MODE", raising=False)
    monkeypatch.setenv("SENTINEL_API_URL", "http://backend:9000/")
    client = get_client()
    assert isinstance(client, SentinelApiClient)
    assert client.base_url == "http://backend:9000"


def test_get_client_mock_mode(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_MODE", "mock")
    assert get_client().is_mock is True


def test_get_client_rejects_unknown_mode(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_MODE", "demo")
    with pytest.raises(ValueError):
        get_client()


# --- Contract rules ----------------------------------------------------------

@pytest.mark.parametrize(
    ("prediction", "anomaly", "expected"),
    [
        ("BENIGN", False, "None"),
        ("BENIGN", True, "Low"),
        ("PortScan", False, "Medium"),
        ("BruteForce", False, "High"),
        ("Bot", False, "High"),
        ("DoS", False, "High"),
        ("DDoS", False, "Critical"),
        ("DDoS", True, "Critical"),  # anomaly flag does not change attack severity
    ],
)
def test_severity_rules(prediction, anomaly, expected):
    assert severity_for(prediction, anomaly) == expected


def test_severity_rejects_unknown_class():
    with pytest.raises(ValueError):
        severity_for("Infiltration")


@pytest.mark.parametrize(
    ("confidence", "band"),
    [(1.0, "strong"), (0.90, "strong"), (0.8999, "moderate"), (0.60, "moderate"), (0.5999, "weak"), (0.0, "weak")],
)
def test_confidence_bands(confidence, band):
    assert confidence_band_for(confidence) == band


@pytest.mark.parametrize("bad", [-0.01, 1.01])
def test_confidence_out_of_range(bad):
    with pytest.raises(ValueError):
        confidence_band_for(bad)


def test_weak_attack_needs_review_but_keeps_severity():
    weak = result("DDoS", 0.55)
    assert weak.needs_review
    assert weak.severity == "Critical"


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("BENIGN", "BENIGN"),
        (" DoS slowloris ", "DoS"),
        ("DoS Slowloris", "DoS"),
        ("DoS Slowhttptest", "DoS"),
        ("DoS Hulk", "DoS"),
        ("DoS GoldenEye", "DoS"),
        ("DDoS", "DDoS"),
        ("PortScan", "PortScan"),
        ("FTP-Patator", "BruteForce"),
        ("SSH-Patator", "BruteForce"),
        ("Bot", "Bot"),
        ("Heartbleed", None),
        ("Infiltration", None),
        ("Web Attack – Brute Force", None),
        ("Web Attack � XSS", None),
        (None, None),
    ],
)
def test_label_mapping(label, expected):
    assert map_label(label) == expected


def test_excluded_and_unknown_labels_are_distinguished():
    assert is_known_label("Web Attack \x96 Sql Injection")
    assert is_known_label("Heartbleed")
    assert not is_known_label("Totally New Attack")


def test_build_summary_always_has_every_key():
    summary = build_summary([result("BENIGN"), result("PortScan", index=1)], total_rows=3)
    assert set(summary.by_class) == set(DETECTION_CLASSES)
    assert set(summary.by_severity) == {"None", "Low", "Medium", "High", "Critical"}
    assert summary.skipped_rows == 1
    assert summary.by_severity["Medium"] == 1


# --- Offline mock ------------------------------------------------------------

def test_mock_detection_matches_contract_and_is_marked_mock():
    batch = MockSentinelApi().detect_csv("flows.csv", SAMPLE_CSV)

    assert batch.is_mock is True
    assert batch.detection_method == "Mock"
    assert batch.summary.total_rows == 3
    assert [r.row_index for r in batch.results] == [0, 1, 2]
    for row in batch.results:
        assert row.severity == severity_for(row.prediction, row.is_anomaly)
        assert row.confidence_band == confidence_band_for(row.confidence)
    assert [r.true_class for r in batch.results] == ["BENIGN", "DDoS", "BruteForce"]
    assert batch.results[0].flow.destination_port == 80

    # The mock's JSON must be accepted by the live client's validation too.
    DetectionBatchResponse.model_validate(json.loads(batch.model_dump_json()))


def test_mock_is_repeatable_for_the_same_file():
    api = MockSentinelApi()
    first = api.detect_csv("flows.csv", SAMPLE_CSV)
    second = api.detect_csv("flows.csv", SAMPLE_CSV)
    assert [r.prediction for r in first.results] == [r.prediction for r in second.results]


def test_mock_accepts_cicids_duplicate_header_like_pandas():
    columns = MockSentinelApi().validate_csv("flows.csv", SAMPLE_CSV).columns
    assert "Fwd Header Length" in columns
    assert "Fwd Header Length.1" in columns


def test_mock_reads_cp1252_labels():
    content = b"Flow Duration,Label\n10,Web Attack \x96 XSS\n"
    batch = MockSentinelApi().detect_csv("flows.csv", content)
    assert batch.results[0].true_label == "Web Attack – XSS"
    assert batch.results[0].true_class is None


@pytest.mark.parametrize(
    ("filename", "content", "status", "message"),
    [
        ("flows.txt", SAMPLE_CSV, 400, "Only CSV files"),
        ("flows.csv", b"", 400, "empty"),
        ("flows.csv", b"a,b\n", 400, "no data rows"),
        ("flows.csv", b"a, a ,b\n1,2,3\n", 400, "duplicate column"),
        ("flows.csv", b"a,,b\n1,2,3\n", 400, "cannot be empty"),
        ("flows.csv", b"a,b\n1,2,3\n", 400, "Could not read"),
        ("flows.csv", b"a\n" + b"1\n" * (6 * 1024 * 1024), 413, "too large"),
    ],
    ids=["extension", "empty", "no-rows", "duplicate", "blank-header", "extra-fields", "too-large"],
)
def test_mock_rejects_invalid_uploads_like_backend(filename, content, status, message):
    with pytest.raises(ApiRequestError, match=message) as excinfo:
        MockSentinelApi().validate_csv(filename, content)
    assert excinfo.value.status_code == status


def test_mock_model_info_is_marked_mock():
    info = MockSentinelApi().model_info()
    assert info.is_mock is True
    assert info.classes == list(DETECTION_CLASSES)
