# Sentinel AI — Streamlit frontend

The Streamlit dashboard consumes the FastAPI backend through the frontend API client and typed contract models.

## Components

| File | Purpose |
|---|---|
| dashboard.py | Multi-page Streamlit dashboard (pages below) |
| presentation.py | Display rules and table builders (wording for confidence, severity, anomaly and mock data), unit-tested without Streamlit |
| api_contract.py | Pydantic models and shared severity/confidence/label rules |
| api_client.py | Live FastAPI HTTP client and typed error handling |
| mock_api.py | Offline contract-compatible mock; every detection is marked is_mock=True |

## Pages

| Page | Shows |
|---|---|
| Overview | Benign/malicious/anomaly/skipped counts, class and severity distributions, top alerts for the latest run |
| Network Traffic Analysis | CSV upload, **Validate CSV** (`POST /upload-csv`), **Run detection** (`POST /detect`), traffic breakdown by protocol/port/IP, filterable row-level results, row errors |
| Threat Alerts | Classifier alerts and anomaly-only alerts in separate tabs, each with severity, model confidence, anomaly status, flow and evidence |
| Incident History | Detection runs from this browser session, plus a **sample** incident log (`GET /incidents` is Phase 2 of the contract) |

The sidebar shows backend health (`GET /health`) and model/contract details (`GET /model/info`).

## Run the live dashboard

From the repository root:

```bash
pip install -r requirements-frontend.txt
uvicorn src.backend.main:app --reload --port 8000
python -m streamlit run src/frontend/dashboard.py
```

The default backend URL is http://localhost:8000.

## Mock/offline mode

PowerShell:

```powershell
$env:SENTINEL_API_MODE = "mock"
python -m streamlit run src/frontend/dashboard.py
```

Mock predictions are synthetic and must never be presented as real detections.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| SENTINEL_API_URL | http://localhost:8000 | FastAPI base URL |
| SENTINEL_API_MODE | live | live calls FastAPI; mock uses the offline demo |

## UI behavior

Wording follows contract sections 7, 8 and 10:
- Confidence is shown as "Model confidence 0.72 (moderate)", never as the probability of an attack.
- Weak-confidence attack predictions are labelled "Needs analyst review".
- A benign row flagged by the anomaly detector is shown as "Anomaly — unconfirmed" in its own tab and colour, never as a class. `anomaly: null` is shown as "Not run".
- Every mock result carries the "Mock data — not live detection" banner. Sample incidents are labelled as demonstration data.
- Alerts are ordered by severity, never by confidence.

The dashboard keeps these concepts separate:
- Prediction: one of the six supervised MVP classes.
- Confidence: model certainty, shown as a percentage and confidence band.
- Severity: contract-defined risk level, independent of confidence.
- Anomaly: a separate anomaly signal; it is not a seventh attack class.
- Mock mode: explicitly labelled so synthetic results cannot be mistaken for live detections.

The UI handles backend-unavailable, 4xx CSV rejection, 5xx errors and response contract mismatches without exposing raw exceptions.

## Tests

```bash
python -m pytest tests/test_api_client.py tests/test_presentation.py tests/test_dashboard.py
```
