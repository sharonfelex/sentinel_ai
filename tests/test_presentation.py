"""Tests for the dashboard display rules (contract sections 7, 8 and 10)."""

from datetime import datetime, timezone

from src.frontend import presentation as ui
from src.frontend.api_contract import (
    DetectionBatchResponse,
    DetectionResult,
    build_summary,
    confidence_band_for,
    severity_for,
)
from src.frontend.mock_api import MockSentinelApi


def result(
    prediction="BENIGN",
    confidence=0.95,
    anomaly: bool | None = False,
    index=0,
    flow=None,
    true_label=None,
    true_class=None,
) -> DetectionResult:
    return DetectionResult(
        row_index=index,
        prediction=prediction,
        is_malicious=prediction != "BENIGN",
        confidence=confidence,
        confidence_band=confidence_band_for(confidence),
        severity=severity_for(prediction, bool(anomaly)),
        detection_method="Random Forest",
        anomaly=None if anomaly is None else {"is_anomaly": anomaly, "score": 0.5},
        flow=flow,
        true_label=true_label,
        true_class=true_class,
    )


def batch(results, *, is_mock=False) -> DetectionBatchResponse:
    return DetectionBatchResponse(
        contract_version="0.1",
        request_id="req-1",
        filename="flows.csv",
        processed_at=datetime(2026, 11, 13, 9, 30, tzinfo=timezone.utc),
        is_mock=is_mock,
        model_version="mock" if is_mock else "rf-baseline-0.1",
        detection_method="Mock" if is_mock else "Random Forest",
        summary=build_summary(results, total_rows=len(results)),
        results=results,
    )


def test_confidence_text_never_mentions_attack_probability():
    text = ui.confidence_text(result("DDoS", 0.72))
    assert text == "Model confidence 0.72 (moderate)"
    assert "probab" not in text.lower()


def test_anomaly_text_distinguishes_not_run_from_no_anomaly():
    assert ui.anomaly_text(result(anomaly=None)) == "Not run"
    assert ui.anomaly_text(result(anomaly=False)) == "No"
    assert ui.anomaly_text(result(anomaly=True)) == ui.ANOMALY_LABEL == "Anomaly — unconfirmed"


def test_anomaly_only_alert_is_not_shown_as_a_class():
    anomaly = result("BENIGN", anomaly=True, index=4)
    assert ui.is_anomaly_only(anomaly)
    assert ui.alert_title(anomaly) == "Anomaly — unconfirmed · row 4"
    assert "BENIGN" not in ui.alert_title(anomaly)

    attack_with_anomaly = result("DoS", anomaly=True)
    assert not ui.is_anomaly_only(attack_with_anomaly)
    assert ui.alert_title(attack_with_anomaly).startswith("DoS")


def test_weak_attack_needs_analyst_review():
    assert ui.alert_status(result("PortScan", 0.55)) == "Needs analyst review"
    assert ui.alert_status(result("PortScan", 0.95)) == "Classifier alert"
    assert ui.alert_status(result("BENIGN", 0.55, anomaly=True)) == "Unconfirmed — review traffic"


def test_alerts_sorted_by_severity_not_confidence():
    low_conf_ddos = result("DDoS", 0.61, index=5)
    high_conf_scan = result("PortScan", 0.99, index=1)
    dos = result("DoS", 0.80, index=3)
    ordered = ui.sort_alerts([high_conf_scan, dos, low_conf_ddos])
    assert [r.prediction for r in ordered] == ["DDoS", "DoS", "PortScan"]


def test_classifier_and_anomaly_alerts_are_split():
    b = batch([
        result("BENIGN", index=0),
        result("DDoS", index=1),
        result("BENIGN", anomaly=True, index=2),
        result("Bot", anomaly=True, index=3),
    ])
    assert [r.row_index for r in ui.classifier_alerts(b)] == [1, 3]
    assert [r.row_index for r in ui.anomaly_alerts(b)] == [2]


def test_result_rows_keep_confidence_severity_and_anomaly_separate():
    row = ui.result_rows([result("DDoS", 0.96, anomaly=True, index=7)])[0]
    assert row["Model confidence"] == 0.96
    assert row["Confidence band"] == "strong"
    assert row["Severity"] == "🚨 Critical"
    assert row["Anomaly"] == ui.ANOMALY_LABEL
    assert row["Status"] == "Classifier alert"


def test_result_rows_benign_has_no_status_and_formats_destination():
    flow = {"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "destination_port": 443}
    row = ui.result_rows([result(flow=flow)])[0]
    assert row["Status"] == ""
    assert row["Source IP"] == "10.0.0.1"
    assert row["Destination"] == "10.0.0.2:443"


def test_filter_results():
    results = [
        result("BENIGN", index=0),
        result("DDoS", index=1),
        result("PortScan", index=2),
        result("BENIGN", anomaly=True, index=3),
    ]
    assert len(ui.filter_results(results)) == 4
    assert [r.row_index for r in ui.filter_results(results, classes=["DDoS"])] == [1]
    assert [r.row_index for r in ui.filter_results(results, severities=["Medium", "Low"])] == [2, 3]
    assert [r.row_index for r in ui.filter_results(results, alerts_only=True)] == [1, 2, 3]
    assert ui.filter_results(results, classes=[]) == []


def test_flow_breakdown_counts_malicious_per_value():
    results = [
        result("BENIGN", flow={"destination_port": 80}),
        result("DDoS", flow={"destination_port": 80}, index=1),
        result("DDoS", flow={"destination_port": 80}, index=2),
        result("BruteForce", flow={"destination_port": 22}, index=3),
        result("BENIGN", index=4),  # no flow info: ignored
    ]
    rows = ui.flow_breakdown(results, "destination_port")
    assert rows == [
        {"Destination port": "80", "Flows": 3, "Malicious": 2},
        {"Destination port": "22", "Flows": 1, "Malicious": 1},
    ]
    assert ui.flow_breakdown(results, "source_ip") == []


def test_dataset_agreement():
    assert ui.dataset_agreement([result()]) is None
    results = [
        result("BENIGN", true_label="BENIGN", true_class="BENIGN"),
        result("DDoS", true_label="DDoS", true_class="DDoS", index=1),
        result("DoS", true_label="DDoS", true_class="DDoS", index=2),
        result("BENIGN", true_label="Heartbleed", true_class=None, index=3),
    ]
    assert ui.dataset_agreement(results) == {
        "labelled_rows": 4,
        "comparable_rows": 3,
        "matching_rows": 2,
        "excluded_or_unknown": 1,
    }


def test_run_record_labels_mock_runs():
    mock_run = ui.run_record(batch([result()], is_mock=True))
    assert mock_run["Source"] == "Mock data — not live detection"
    live_run = ui.run_record(batch([result("DDoS")]))
    assert live_run["Source"] == "Live · rf-baseline-0.1"
    assert live_run["Malicious"] == 1
    assert live_run["Processed (UTC)"] == "2026-11-13 09:30:00"


def test_sample_incidents_are_clearly_demo_and_use_contract_values():
    rows = ui.sample_incident_rows()
    assert rows and all(r["Incident"].startswith("DEMO-") for r in rows)
    for incident in ui.SAMPLE_INCIDENTS:
        assert incident.severity == severity_for(
            incident.prediction, incident.prediction == "BENIGN"
        )
    benign = [r for r in rows if r["Incident"] == "DEMO-0004"][0]
    assert benign["Classification"] == ui.ANOMALY_LABEL


def test_presentation_works_on_mock_api_output():
    csv = b"Source IP,Destination IP,Destination Port,Protocol,Flow Duration,Label\n" + b"".join(
        f"10.0.0.{i},192.168.0.1,{80 if i % 2 else 22},6,{i * 10},BENIGN\n".encode()
        for i in range(60)
    )
    b = MockSentinelApi().detect_csv("flows.csv", csv)
    assert len(ui.result_rows(b.results)) == 60
    alerts = ui.classifier_alerts(b) + ui.anomaly_alerts(b)
    assert len(alerts) == len(b.alerts)
    assert sum(r["Flows"] for r in ui.flow_breakdown(b.results, "destination_port")) == 60
