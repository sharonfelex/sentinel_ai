from fastapi.testclient import TestClient

from src.backend.main import app

client = TestClient(app)


def test_health_contract():
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["mode"] == "mock"
    assert body["model_loaded"] is False


def test_model_info_contract():
    body = client.get("/model/info").json()
    assert body["contract_version"] == "0.1"
    assert body["is_mock"] is True
    assert body["detection_method"] == "Mock"
    assert body["classes"] == ["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "Bot"]


def test_detect_returns_batch_contract():
    csv = b"Flow Duration,Label,Destination Port\n10,BENIGN,80\n20,DDoS,443\n30,SSH-Patator,22\n"
    response = client.post("/detect", files={"file": ("flows.csv", csv, "text/csv")})
    assert response.status_code == 200
    body = response.json()
    assert body["is_mock"] is True
    assert body["model_version"] == "mock"
    assert body["summary"]["total_rows"] == 3
    assert body["summary"]["analyzed_rows"] == 3
    assert body["summary"]["skipped_rows"] == 0
    assert body["summary"]["malicious_count"] == 2
    assert len(body["results"]) == 3
    assert body["results"][1]["prediction"] == "DDoS"
    assert body["results"][1]["severity"] == "Critical"
    assert body["results"][2]["prediction"] == "BruteForce"


def test_upload_rejects_non_csv():
    response = client.post("/upload-csv", files={"file": ("flows.txt", b"a,b\n1,2\n", "text/plain")})
    assert response.status_code == 400


def test_upload_rejects_blank_header():
    response = client.post("/upload-csv", files={"file": ("flows.csv", b"a,,b\n1,2,3\n", "text/csv")})
    assert response.status_code == 400


def test_upload_supports_cp1252():
    csv = "Flow Duration,Label\n10,Web Attack – XSS\n".encode("cp1252")
    response = client.post("/detect", files={"file": ("flows.csv", csv, "text/csv")})
    assert response.status_code == 200
    result = response.json()["results"][0]
    assert result["true_label"] == "Web Attack – XSS"
    assert result["true_class"] is None
