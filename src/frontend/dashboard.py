"""Sentinel AI Streamlit security dashboard.

Pages: Overview, Network Traffic Analysis, Threat Alerts and Incident History.

The dashboard talks to the backend only through the frontend API boundary
(``api_client.get_client``), so it runs against the live FastAPI service or the
contract-compatible offline mock (``SENTINEL_API_MODE=mock``). Display wording
rules live in ``presentation.py``.

Run from the repository root::

    python -m streamlit run src/frontend/dashboard.py
"""

from __future__ import annotations

from typing import Callable, TypeVar

import pandas as pd
import streamlit as st

from src.frontend.api_client import (
    ApiError,
    ApiRequestError,
    ApiServerError,
    ApiUnavailableError,
    ContractError,
    get_client,
)
from src.frontend.api_contract import (
    DETECTION_CLASSES,
    SEVERITY_LEVELS,
    DetectionBatchResponse,
    DetectionResult,
)
from src.frontend import presentation as ui

T = TypeVar("T")

BATCH_KEY = "latest_batch"
RUNS_KEY = "detection_runs"


@st.cache_resource
def api_client():
    return get_client()


# --- Shared helpers -----------------------------------------------------------


def latest_batch() -> DetectionBatchResponse | None:
    return st.session_state.get(BATCH_KEY)


def call_api(action: str, request: Callable[[], T]) -> T | None:
    """Run one API call behind a spinner and show any failure as a UI message."""
    with st.spinner(f"{action}…"):
        try:
            return request()
        except ApiUnavailableError as exc:
            st.error("The detection backend is unavailable.", icon="🔌")
            st.caption(
                f"{exc} Start it with `uvicorn src.backend.main:app --port 8000`, "
                "or set `SENTINEL_API_MODE=mock` for offline demo data."
            )
        except ApiRequestError as exc:
            st.error("The API rejected the CSV.", icon="📄")
            st.caption(str(exc))
        except ApiServerError as exc:
            st.error("The backend failed while handling the request.", icon="⚠️")
            st.caption(str(exc))
        except ContractError as exc:
            st.error("The backend response does not match the API contract (v0.1).")
            st.caption(str(exc))
        except ApiError as exc:
            st.error(str(exc))
    return None


def mock_banner(batch: DetectionBatchResponse | None = None) -> None:
    """Contract section 10: mock output always carries a visible banner."""
    if batch is not None and batch.is_mock:
        st.warning(
            f"**{ui.MOCK_BANNER}.** These results come from "
            f"`{batch.detection_method}` (model version `{batch.model_version}`) "
            "and are not evidence of a real attack.",
            icon="⚠️",
        )


def no_results_yet() -> None:
    st.info("No detection results yet. Upload a CSV on the Network Traffic Analysis page.")
    st.page_link(PAGES["analysis"], label="Go to Network Traffic Analysis", icon="📡")


def ordered_counts(counts: dict[str, int], order: tuple[str, ...], name: str) -> pd.DataFrame:
    return pd.DataFrame(
        {name: list(order), "Rows": [counts.get(key, 0) for key in order]}
    ).set_index(name)


def show_table(rows: list[dict], *, height: int | None = None) -> None:
    kwargs = {"height": height} if height else {}
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True, **kwargs)


def show_alert_card(result: DetectionResult) -> None:
    """One alert. Anomaly-only alerts are styled apart from classifier alerts."""
    with st.container(border=True):
        if ui.is_anomaly_only(result):
            st.markdown(f"#### :violet[◆ {ui.alert_title(result)}]")
            st.caption(
                "The anomaly detector flagged this flow, but the classifier predicted "
                "BENIGN. It is not an attack classification."
            )
        else:
            st.markdown(f"#### :red[▲ {ui.alert_title(result)}]")

        a, b, c, d = st.columns(4)
        a.markdown(f"**Severity**  \n{ui.severity_label(result.severity)}")
        b.markdown(f"**{ui.confidence_text(result)}**")
        c.markdown(f"**Anomaly**  \n{ui.anomaly_text(result)}")
        d.markdown(f"**Status**  \n{ui.alert_status(result)}")

        if result.needs_review:
            st.warning(
                f"{ui.NEEDS_REVIEW_LABEL}: weak model confidence for an attack prediction.",
                icon="🔎",
            )
        if result.flow:
            st.json(result.flow.model_dump(exclude_none=True), expanded=False)
        if result.evidence:
            st.markdown("**Evidence** (features that contributed most)")
            show_table([e.model_dump() for e in result.evidence])
        if result.true_label:
            st.caption(
                f"Dataset label: {result.true_label} → "
                f"{result.true_class or 'excluded/unknown'}"
            )


# --- Pages --------------------------------------------------------------------


def overview_page() -> None:
    st.title("🛡️ Overview")
    st.caption("Summary of the most recent detection run")

    batch = latest_batch()
    if batch is None:
        no_results_yet()
        return

    mock_banner(batch)
    summary = batch.summary
    st.caption(
        f"File **{batch.filename}** · processed {batch.processed_at:%Y-%m-%d %H:%M:%S} UTC "
        f"· method {batch.detection_method} · request `{batch.request_id}`"
    )

    c = st.columns(5)
    c[0].metric("Rows", summary.total_rows)
    c[1].metric("Benign", summary.benign_count)
    c[2].metric("Malicious", summary.malicious_count)
    c[3].metric("Anomalies (unconfirmed)", summary.anomaly_count)
    c[4].metric("Skipped", summary.skipped_rows)

    left, right = st.columns(2)
    with left:
        st.subheader("Predictions by class")
        st.bar_chart(ordered_counts(summary.by_class, DETECTION_CLASSES, "Class"), sort=False)
    with right:
        st.subheader("Rows by severity")
        st.bar_chart(ordered_counts(summary.by_severity, SEVERITY_LEVELS, "Severity"), sort=False)

    st.subheader("Alert summary")
    attacks = ui.classifier_alerts(batch)
    anomalies = ui.anomaly_alerts(batch)
    needs_review = sum(1 for r in attacks if r.needs_review)
    a, b, c = st.columns(3)
    a.metric("Classifier alerts", len(attacks))
    b.metric(ui.ANOMALY_LABEL, len(anomalies))
    c.metric(ui.NEEDS_REVIEW_LABEL, needs_review)

    if attacks or anomalies:
        show_table(ui.result_rows((attacks + anomalies)[:5]))
        st.page_link(PAGES["alerts"], label="Open all threat alerts", icon="🚨")
    else:
        st.success("No classifier or anomaly alerts in this run.")


def analysis_page() -> None:
    st.title("📡 Network Traffic Analysis")
    st.caption("Upload CICIDS2017-format flows, validate them and run detection")

    client = api_client()
    upload = st.file_uploader("CICIDS-style CSV file (max 10 MB)", type=["csv"])

    if upload is not None:
        st.caption(f"Selected: {upload.name} · {upload.size:,} bytes")
        validate_col, detect_col = st.columns(2)
        validate = validate_col.button("Validate CSV", width="stretch")
        detect = detect_col.button("Run detection", type="primary", width="stretch")

        if validate:
            check = call_api(
                "Validating CSV", lambda: client.validate_csv(upload.name, upload.getvalue())
            )
            if check is not None:
                st.success(check.message)
                st.write(f"{check.total_rows:,} rows · {check.total_columns} columns")
                if check.missing_features:
                    st.warning(
                        "Missing required features: " + ", ".join(check.missing_features)
                    )
                if check.ready_for_detection is False:
                    st.warning("The backend reports this file is not ready for detection.")

        if detect:
            batch = call_api(
                "Running detection", lambda: client.detect_csv(upload.name, upload.getvalue())
            )
            if batch is not None:
                st.session_state[BATCH_KEY] = batch
                st.session_state.setdefault(RUNS_KEY, []).insert(0, ui.run_record(batch))
                st.success(f"Analysis complete · request `{batch.request_id}`")

    batch = latest_batch()
    if batch is None:
        if upload is None:
            st.info("Upload a CSV to run detection.")
        return

    st.divider()
    mock_banner(batch)
    st.subheader(f"Results for {batch.filename}")

    agreement = ui.dataset_agreement(batch.results)
    if agreement:
        st.caption(
            f"The CSV has a Label column: {agreement['matching_rows']} of "
            f"{agreement['comparable_rows']} comparable rows match the dataset label "
            f"({agreement['excluded_or_unknown']} excluded/unknown labels). "
            "This is a sanity check, not an evaluation metric."
        )

    tabs = st.tabs(["Traffic breakdown", "Row-level results", "Row errors"])
    with tabs[0]:
        shown = False
        cols = st.columns(2)
        for i, field in enumerate(ui.FLOW_FIELDS):
            rows = ui.flow_breakdown(batch.results, field)
            if rows:
                shown = True
                with cols[i % 2]:
                    st.markdown(f"**Flows by {ui.FLOW_FIELDS[field]}**")
                    show_table(rows)
        if not shown:
            st.info(
                "The CSV has no flow identifier columns (Source IP, Destination IP, "
                "Destination Port, Protocol), so there is no traffic breakdown."
            )

    with tabs[1]:
        f1, f2, f3 = st.columns([2, 2, 1])
        classes = f1.multiselect("Class", DETECTION_CLASSES, default=list(DETECTION_CLASSES))
        severities = f2.multiselect("Severity", SEVERITY_LEVELS, default=list(SEVERITY_LEVELS))
        alerts_only = f3.toggle("Alerts only")
        rows = ui.filter_results(
            batch.results, classes=classes, severities=severities, alerts_only=alerts_only
        )
        st.caption(f"{len(rows)} of {len(batch.results)} analysed rows")
        show_table(ui.result_rows(rows), height=420)

    with tabs[2]:
        if batch.row_errors:
            st.warning(
                f"{batch.summary.skipped_rows} row(s) could not be analysed"
                + (" (first 100 shown)." if batch.summary.skipped_rows > 100 else ".")
            )
            show_table([e.model_dump() for e in batch.row_errors])
        else:
            st.success("Every row was analysed.")


def alerts_page() -> None:
    st.title("🚨 Threat Alerts")
    st.caption(
        "Classifier alerts and anomaly alerts are shown separately. "
        "Severity comes from contract rules and never from confidence."
    )

    batch = latest_batch()
    if batch is None:
        no_results_yet()
        return
    mock_banner(batch)

    severities = st.multiselect(
        "Severity", SEVERITY_LEVELS[1:], default=list(SEVERITY_LEVELS[1:])
    )
    attacks = ui.filter_results(ui.classifier_alerts(batch), severities=severities)
    anomalies = ui.filter_results(ui.anomaly_alerts(batch), severities=severities)

    tab_attacks, tab_anomalies = st.tabs(
        [f"▲ Classifier alerts ({len(attacks)})", f"◆ {ui.ANOMALY_LABEL} ({len(anomalies)})"]
    )
    with tab_attacks:
        if not attacks:
            st.success("No attack predictions match the filter.")
        for result in attacks[:50]:
            show_alert_card(result)
        if len(attacks) > 50:
            st.caption(f"Showing 50 of {len(attacks)}. See the row-level results table for all.")

    with tab_anomalies:
        st.info(
            "Anomaly alerts come from the anomaly detector. They are not a seventh attack "
            "class and need analyst review before being treated as incidents.",
            icon="🔷",
        )
        if not anomalies:
            st.success("No anomaly-only alerts match the filter.")
        for result in anomalies[:50]:
            show_alert_card(result)
        if len(anomalies) > 50:
            st.caption(f"Showing 50 of {len(anomalies)}.")


def incidents_page() -> None:
    st.title("🗂️ Incident History")

    st.subheader("Detection runs this session")
    runs = st.session_state.get(RUNS_KEY, [])
    if runs:
        show_table(runs)
    else:
        st.caption("No detection runs yet in this browser session.")

    st.subheader("Incident log")
    st.warning(
        "**Sample data — demonstration only.** Incident storage (`GET /incidents`) "
        "is Phase 2 of the API contract. These records are fixed examples, not real "
        "detections.",
        icon="🧪",
    )
    show_table(ui.sample_incident_rows())


PAGES = {
    "overview": st.Page(overview_page, title="Overview", icon="🛡️", default=True),
    "analysis": st.Page(analysis_page, title="Network Traffic Analysis", icon="📡"),
    "alerts": st.Page(alerts_page, title="Threat Alerts", icon="🚨"),
    "incidents": st.Page(incidents_page, title="Incident History", icon="🗂️"),
}


# --- Sidebar and entry point ----------------------------------------------------


def show_connection(client) -> None:
    st.header("Connection")
    try:
        health = client.health()
    except ApiError as exc:
        st.error("Backend unavailable" if isinstance(exc, ApiUnavailableError) else "Health check failed")
        st.caption(str(exc))
        return

    st.success("API online" if health.is_ok else "API degraded")
    mode = health.mode or ("mock" if client.is_mock else "unknown")
    loaded = {True: "Yes", False: "No", None: "Unknown"}[health.model_loaded]
    st.write(f"**Mode:** {mode.upper()}  \n**Model loaded:** {loaded}")
    st.caption(f"Source: `{getattr(client, 'base_url', 'unknown')}`")

    with st.expander("Model and contract"):
        try:
            info = client.model_info()
        except ApiError as exc:
            st.caption(str(exc))
            return
        st.write(
            f"**Contract:** {info.contract_version}  \n"
            f"**Model:** {info.model_version}  \n"
            f"**Method:** {info.detection_method}  \n"
            f"**Anomaly method:** {info.anomaly_method or '—'}  \n"
            f"**Mock:** {'Yes' if info.is_mock else 'No'}  \n"
            f"**Features:** {len(info.features)}"
        )
        if info.metrics:
            st.json(info.metrics, expanded=False)


def main() -> None:
    st.set_page_config(page_title="Sentinel AI | Security Dashboard", page_icon="🛡️", layout="wide")
    client = api_client()
    navigation = st.navigation(list(PAGES.values()))

    with st.sidebar:
        show_connection(client)
        st.divider()
        st.caption(
            "Confidence is model certainty. Severity is a contract rule based on "
            "the predicted class. Anomaly is a separate signal, not a class."
        )

    if client.is_mock:
        st.warning(
            f"**{ui.MOCK_BANNER}** — offline demo mode (`SENTINEL_API_MODE=mock`). "
            "Predictions are synthetic.",
            icon="⚠️",
        )

    navigation.run()


if __name__ == "__main__":
    main()
