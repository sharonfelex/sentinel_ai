# Sentinel AI — Streamlit frontend

The Streamlit dashboard consumes the FastAPI backend through the frontend API client and typed contract models.

## Components

| File | Purpose |
|---|---|
| dashboard.py | Streamlit security dashboard: connection status, model info, upload, summary, alerts and row-level results |
| api_contract.py | Pydantic models and shared severity/confidence/label rules |
| api_client.py | Live FastAPI HTTP client and typed error handling |
| mock_api.py | Offline contract-compatible mock; every detection is marked is_mock=True |

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

The dashboard keeps these concepts separate:
- Prediction: one of the six supervised MVP classes.
- Confidence: model certainty, shown as a percentage and confidence band.
- Severity: contract-defined risk level, independent of confidence.
- Anomaly: a separate anomaly signal; it is not a seventh attack class.
- Mock mode: explicitly labelled so synthetic results cannot be mistaken for live detections.

The UI handles backend-unavailable, 4xx CSV rejection, 5xx errors and response contract mismatches without exposing raw exceptions.

## Tests

```bash
python -m pytest tests/test_api_client.py
```
