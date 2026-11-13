"""The frontend API client against the real FastAPI app (contract v0.1).

Uses FastAPI's in-process TestClient as the client's HTTP transport, so every
endpoint response goes through the same contract validation the dashboard uses.
"""

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from src.backend.main import app  # noqa: E402
from src.frontend.api_client import (  # noqa: E402
    ApiRequestError,
    SentinelApiClient,
    _error_message,
)
from src.frontend.api_contract import CONTRACT_VERSION, DETECTION_CLASSES  # noqa: E402
from src.frontend.presentation import anomaly_alerts, classifier_alerts  # noqa: E402

CSV = (
    b" Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol,"
    b" Timestamp, Flow Duration, Label\n"
    b"f0,10.0.0.1,51000,192.168.10.50,80,6,7/7/2017 3:30,1200,BENIGN\n"
    b"f1,10.0.0.2,51001,192.168.10.50,80,6,7/7/2017 3:30,3500,DDoS\n"
    b"f2,10.0.0.3,51002,192.168.10.50,22,6,7/7/2017 3:31,90,SSH-Patator\n"
    b"f3,10.0.0.4,51003,192.168.10.50,80,6,7/7/2017 3:31,10,DoS slowloris\n"
    b"f4,10.0.0.5,51004,192.168.10.3,53,17,7/7/2017 3:32,15,BENIGN\n"
    b"f5,10.0.0.6,51005,192.168.10.50,0,6,7/7/2017 3:32,12,Heartbleed\n"
)


@pytest.fixture
def client():
    with TestClient(app) as http:
        yield SentinelApiClient(base_url="http://testserver", http_client=http)


def test_health(client):
    health = client.health()
    assert health.is_ok
    assert health.mode in {"mock", "model"}


def test_model_info(client):
    info = client.model_info()
    assert info.contract_version == CONTRACT_VERSION
    assert tuple(info.classes) == DETECTION_CLASSES
    assert info.is_mock == (info.model_version == "mock")


def test_upload_csv_validates_without_detection(client):
    check = client.validate_csv("flows.csv", CSV)
    assert check.total_rows == 6
    assert "Flow Duration" in check.columns  # header whitespace stripped


def test_detect_matches_contract_and_dashboard_views(client):
    batch = client.detect_csv("flows.csv", CSV)
    assert batch.contract_version == CONTRACT_VERSION
    assert batch.summary.total_rows == 6
    assert batch.summary.analyzed_rows + batch.summary.skipped_rows == 6
    if batch.is_mock:
        assert batch.detection_method == "Mock" and batch.model_version == "mock"

    for r in batch.results:
        assert r.flow is not None and r.flow.destination_ip
        if r.true_label == "Heartbleed":
            assert r.true_class is None  # excluded from the MVP

    by_row = {r.row_index: r for r in batch.results}
    assert by_row[4].anomaly is not None and by_row[4].anomaly.is_anomaly
    assert [r.row_index for r in anomaly_alerts(batch)] == [4]
    assert by_row[4].severity == "Low"  # benign + anomaly (contract 7.1)
    assert {r.prediction for r in classifier_alerts(batch)} <= set(DETECTION_CLASSES) - {"BENIGN"}


@pytest.mark.parametrize(
    "filename, content, status",
    [
        ("flows.txt", CSV, 400),
        ("flows.csv", b"", 400),
        ("flows.csv", b"a,b\n", 400),
        ("flows.csv", b"a,b\n" + b"1,2\n" * (6 * 1024 * 1024), 413),
    ],
)
def test_rejected_uploads_raise_request_error(client, filename, content, status):
    for call in (client.validate_csv, client.detect_csv):
        with pytest.raises(ApiRequestError) as exc:
            call(filename, content)
        assert exc.value.status_code == status
        assert exc.value.message  # shown to the user as-is


def test_missing_file_field_list_detail_is_readable():
    """FastAPI's own 422 has a list ``detail``; the client turns it into text."""
    with TestClient(app) as http:
        response = http.post("/detect")  # no file field
    assert response.status_code == 422
    message = _error_message(response)
    assert "file" in message and "Field required" in message
