"""Sentinel AI Streamlit security dashboard.

The dashboard depends only on the frontend API boundary and can run against
the live FastAPI service or the contract-compatible offline mock.
"""

from __future__ import annotations

from typing import Any

import streamlit as st

from src.frontend.api_client import (
    ApiError,
    ApiRequestError,
    ApiUnavailableError,
    ContractError,
    get_client,
)
from src.frontend.api_contract import DetectionBatchResponse, DetectionResult


st.set_page_config(
    page_title="Sentinel AI | Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_resource
def api_client():
    return get_client()


def severity_emoji(severity: str) -> str:
    return {
        "None": "🟢",
        "Low": "🟡",
        "Medium": "🟠",
        "High": "🔴",
        "Critical": "🚨",
    }.get(severity, "⚪")


def result_rows(results: list[DetectionResult]) -> list[dict[str, Any]]:
    return [
        {
            "Row": r.row_index,
            "Prediction": r.prediction,
            "Malicious": "Yes" if r.is_malicious else "No",
            "Confidence": f"{r.confidence:.1%}",
            "Band": r.confidence_band,
            "Severity": f"{severity_emoji(r.severity)} {r.severity}",
            "Anomaly": "Yes" if r.is_anomaly else "No",
            "Method": r.detection_method,
        }
        for r in results
    ]


def show_backend_status(client) -> None:
    try:
        health = client.health()
    except ApiUnavailableError as exc:
        st.sidebar.error("Backend unavailable")
        st.sidebar.caption(str(exc))
        return
    except ApiError as exc:
        st.sidebar.error("Health check failed")
        st.sidebar.caption(str(exc))
        return

    st.sidebar.success("API online" if health.is_ok else "API degraded")
    mode = health.mode or ("mock" if client.is_mock else "live")
    loaded = "Yes" if health.model_loaded else "No"
    st.sidebar.write(f"**Mode:** {mode.upper()}")
    st.sidebar.write(f"**Model loaded:** {loaded}")


def show_model_info(client) -> None:
    with st.expander("Model and contract information"):
        try:
            info = client.model_info()
        except ApiError as exc:
            st.warning(str(exc))
            return

        c = st.columns(4)
        c[0].metric("Contract", info.contract_version)
        c[1].metric("Model", info.model_version)
        c[2].metric("Method", info.detection_method)
        c[3].metric("Mock", "Yes" if info.is_mock else "No")

        if info.classes:
            st.write("**Classes:** " + ", ".join(info.classes))
        if info.features:
            st.write(f"**Model features:** {len(info.features)}")


def show_summary(batch: DetectionBatchResponse) -> None:
    summary = batch.summary
    c = st.columns(5)
    c[0].metric("Rows", summary.total_rows)
    c[1].metric("Analyzed", summary.analyzed_rows)
    c[2].metric("Malicious", summary.malicious_count)
    c[3].metric("Anomalies", summary.anomaly_count)
    c[4].metric("Skipped", summary.skipped_rows)

    st.subheader("Detection distribution")
    st.bar_chart({k: v for k, v in summary.by_class.items() if v})

    st.subheader("Severity distribution")
    st.bar_chart({k: v for k, v in summary.by_severity.items() if v})


def show_alerts(batch: DetectionBatchResponse) -> None:
    alerts = batch.alerts
    st.subheader(f"Alerts ({len(alerts)})")

    if not alerts:
        st.success("No malicious flows or anomaly alerts in this batch.")
        return

    st.dataframe(result_rows(alerts), use_container_width=True, hide_index=True)

    with st.expander("Alert details"):
        for result in alerts[:50]:
            anomaly_text = "Yes" if result.is_anomaly else "No"
            with st.container(border=True):
                st.write(
                    f"**Row {result.row_index} — "
                    f"{severity_emoji(result.severity)} {result.prediction}**"
                )
                a, b, c = st.columns(3)
                a.write(
                    f"Confidence: **{result.confidence:.1%}** "
                    f"({result.confidence_band})"
                )
                b.write(f"Severity: **{result.severity}**")
                c.write(f"Anomaly: **{anomaly_text}**")

                if result.flow:
                    st.json(result.flow.model_dump(exclude_none=True))

                if result.evidence:
                    st.write("**Evidence**")
                    st.dataframe(
                        [e.model_dump() for e in result.evidence],
                        use_container_width=True,
                        hide_index=True,
                    )

                if result.true_label:
                    true_class = result.true_class or "excluded/unknown"
                    st.caption(
                        f"Dataset label: {result.true_label} → {true_class}"
                    )


def show_results(batch: DetectionBatchResponse) -> None:
    st.subheader("Row-level results")
    st.dataframe(
        result_rows(batch.results),
        use_container_width=True,
        hide_index=True,
    )

    if batch.row_errors:
        st.warning(f"{len(batch.row_errors)} row(s) could not be analyzed.")
        st.dataframe(
            [error.model_dump() for error in batch.row_errors],
            use_container_width=True,
            hide_index=True,
        )


def main() -> None:
    st.title("🛡️ Sentinel AI")
    st.caption("Network intrusion detection and security analytics")

    client = api_client()

    with st.sidebar:
        st.header("Connection")
        show_backend_status(client)
        st.divider()
        st.caption(
            "Confidence describes model certainty. Severity describes "
            "contract-defined risk; they are separate."
        )

    if client.is_mock:
        st.warning(
            "DEMO / MOCK MODE — predictions are synthetic and are NOT live detections.",
            icon="⚠️",
        )

    show_model_info(client)

    st.header("Analyze network traffic")
    upload = st.file_uploader(
        "Upload a CICIDS-style CSV file",
        type=["csv"],
    )

    if upload is None:
        st.info("Upload a CSV to run detection.")
        return

    st.caption(f"Selected: {upload.name} · {upload.size:,} bytes")

    if not st.button("Run detection", type="primary", use_container_width=True):
        return

    with st.spinner("Sending traffic to the detection API…"):
        try:
            batch = client.detect_csv(upload.name, upload.getvalue())
        except ApiUnavailableError as exc:
            st.error("The detection backend is unavailable.")
            st.info(str(exc))
            return
        except ApiRequestError as exc:
            st.error("The CSV was rejected by the API.")
            st.info(str(exc))
            return
        except ContractError as exc:
            st.error("The backend response does not match the frontend contract.")
            st.info(str(exc))
            return
        except ApiError as exc:
            st.error(str(exc))
            return

    if batch.is_mock:
        st.warning(
            "This result is MOCK data. Do not use it as evidence of a real attack.",
            icon="⚠️",
        )

    st.success(f"Analysis complete · request {batch.request_id}")
    show_summary(batch)
    show_alerts(batch)
    show_results(batch)


if __name__ == "__main__":
    main()
