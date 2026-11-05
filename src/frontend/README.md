# Sentinel AI — Frontend API client

The Streamlit dashboard talks to the FastAPI backend only through this package.
The API contract it implements is `docs/architecture/api-contract.md` (v0.1).

| File | Purpose |
|---|---|
| `api_contract.py` | Pydantic models for every API response, plus the shared severity, confidence-band and label-mapping rules |
| `api_client.py` | `SentinelApiClient` (live HTTP client), error types and `get_client()` |
| `mock_api.py` | `MockSentinelApi`, an offline mock with the same interface. Its output is always marked `is_mock=True`. |

## Setup

From the repository root:

```bash
pip install -r requirements-frontend.txt
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SENTINEL_API_URL` | `http://localhost:8000` | Backend base URL |
| `SENTINEL_API_MODE` | `live` | `live` calls the backend; `mock` uses offline demo data |

## Run

Start the backend (Sharan's `feature/backend-api`):

```bash
uvicorn src.backend.main:app --reload --port 8000
```

Start the dashboard. Use `python -m` so the repository root is on the import path:

```bash
python -m streamlit run src/frontend/dashboard.py
```

To work on the dashboard without a backend, set `SENTINEL_API_MODE=mock` first (PowerShell: `$env:SENTINEL_API_MODE = "mock"`).

## Using the client in the dashboard

```python
import streamlit as st
from src.frontend.api_client import ApiError, ApiUnavailableError, get_client

@st.cache_resource
def api():
    return get_client()

upload = st.file_uploader("Network flow CSV", type="csv")
if upload is not None:
    try:
        batch = api().detect_csv(upload.name, upload.getvalue())
    except ApiUnavailableError:
        st.error("The detection API is not reachable. Is the backend running?")
    except ApiError as exc:
        st.error(str(exc))
    else:
        if batch.is_mock:
            st.warning("Mock data — not live detection")
        st.metric("Malicious flows", batch.summary.malicious_count)
        for alert in batch.alerts:
            ...
```

## Error types

All errors inherit from `ApiError`, so the UI can catch that one type and show `str(exc)`.

| Error | When |
|---|---|
| `ApiUnavailableError` | Backend not running, unreachable, or timed out |
| `ApiRequestError` | Backend rejected the request (4xx), such as an invalid CSV or an endpoint that doesn't exist yet |
| `ApiServerError` | Backend failed (5xx) |
| `ContractError` | Backend answered, but the response does not match the contract |

## Tests

```bash
python -m pytest tests/test_api_client.py
```
