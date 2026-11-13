"""Smoke tests: every dashboard page renders without errors in offline mock mode."""

from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

from src.frontend.mock_api import MockSentinelApi  # noqa: E402

DASHBOARD = Path(__file__).resolve().parents[1] / "src" / "frontend" / "dashboard.py"

CSV = b"Source IP,Destination IP,Destination Port,Protocol,Flow Duration,Label\n" + b"".join(
    f"10.0.0.{i},192.168.0.1,{80 if i % 2 else 22},6,{i * 10},BENIGN\n".encode()
    for i in range(80)
)


def _page_script(page: str) -> None:
    from src.frontend import dashboard

    getattr(dashboard, page)()


@pytest.fixture(autouse=True)
def mock_mode(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_MODE", "mock")


@pytest.fixture
def batch():
    return MockSentinelApi().detect_csv("flows.csv", CSV)


def run_page(page: str, batch=None) -> AppTest:
    at = AppTest.from_function(_page_script, args=(page,), default_timeout=30)
    if batch is not None:
        at.session_state["latest_batch"] = batch
        at.session_state["detection_runs"] = []
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    return at


def test_full_app_starts_on_overview_with_mock_banner():
    at = AppTest.from_file(str(DASHBOARD), default_timeout=30).run()
    assert not at.exception, [e.value for e in at.exception]
    assert any("Mock data — not live detection" in w.value for w in at.warning)
    assert any("Overview" in t.value for t in at.title)


@pytest.mark.parametrize("page", ["overview_page", "alerts_page"])
def test_pages_without_results_point_to_analysis(page):
    at = run_page(page)
    assert any("No detection results yet" in i.value for i in at.info)


@pytest.mark.parametrize(
    "page", ["overview_page", "analysis_page", "alerts_page", "incidents_page"]
)
def test_pages_render_mock_results_with_banner(page, batch):
    at = run_page(page, batch)
    warnings = " ".join(w.value for w in at.warning)
    if page == "incidents_page":
        assert "Sample data — demonstration only" in warnings
    else:
        assert "Mock data — not live detection" in warnings


def test_overview_metrics_match_summary(batch):
    at = run_page("overview_page", batch)
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Rows"] == str(batch.summary.total_rows)
    assert metrics["Malicious"] == str(batch.summary.malicious_count)
    assert metrics["Anomalies (unconfirmed)"] == str(batch.summary.anomaly_count)


def test_analysis_page_filters_rows(batch):
    at = run_page("analysis_page", batch)
    at.toggle[0].set_value(True).run()
    assert not at.exception
    assert any(
        f"{len(batch.alerts)} of {len(batch.results)} analysed rows" in c.value
        for c in at.caption
    )
