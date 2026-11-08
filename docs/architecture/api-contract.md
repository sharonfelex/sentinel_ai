# Sentinel AI — Detection API Contract

| | |
|---|---|
| **Contract version** | 0.1 (draft for team confirmation) |
| **Issues** | #4 (API contract), API side of #9 |
| **Prepared by** | Arshan (@arshhn) — API specification & integration coordinator |
| **Needs confirmation from** | Sharan (@sharonfelex) — backend · Abhik (@neopentane7) — ML · Arshan (@arshhn) — frontend |
| **Last updated** | 6 November 2026 |

This document is the single source of truth for how the ML engine, the FastAPI backend and the Streamlit dashboard exchange data. Any change to an endpoint, field or rule must update this file in a pull request and be mentioned in Issue #4.

---

## 1. Endpoint overview

| Method | Path | Purpose | Status |
|---|---|---|---|
| GET | `/` | API information | Implemented (PR #6) |
| GET | `/health` | Liveness check | Implemented (PR #6) |
| POST | `/upload-csv` | Validate a CSV and return its metadata. Does **not** run detection. | Implemented (PR #6) |
| POST | `/detect` | Run detection on a CSV and return per-row results plus a summary | To build: mock output first (#7), real model after #2/#8 |
| GET | `/model/info` | Model version, classes and input feature list | To build (#7) |
| GET | `/incidents`, `/incidents/{incident_id}` | Stored incident history | Phase 2 — not required for the 8 November target |

## 2. Conventions

- **Base URL:** `http://localhost:8000` in development. The dashboard reads it from the `SENTINEL_API_URL` environment variable.
- **Format:** JSON, UTF-8, `snake_case` field names.
- **Timestamps created by the API:** ISO 8601 in UTC, for example `2026-11-06T10:15:00Z`. Timestamps copied from the dataset (`flow.timestamp`) are passed through unchanged as strings.
- **Uploads:** `multipart/form-data` with a single file field named `file`.
- **Authentication:** none for the MVP, which runs locally for the demo. Do not expose the API publicly without adding authentication.
- **Compatibility:** adding a new optional field is non-breaking, and clients must ignore fields they do not recognise. Renaming or removing a field, or changing its type, is breaking: bump `contract_version` and agree the change in #4 first.
- **CORS:** not needed. The Streamlit dashboard calls the API from its Python server process, not from the browser.

## 3. Detection classes and label mapping

The six supervised classes were agreed in #1 and #2:

`BENIGN`, `DoS`, `DDoS`, `PortScan`, `BruteForce`, `Bot`

Anomaly detection is a separate signal (section 8), not a seventh class.

| Original CICIDS2017 label (as spelled in the CSVs) | MVP class |
|---|---|
| `BENIGN` | `BENIGN` |
| `DoS Hulk`, `DoS GoldenEye`, `DoS slowloris`, `DoS Slowhttptest` | `DoS` |
| `DDoS` | `DDoS` |
| `PortScan` | `PortScan` |
| `FTP-Patator`, `SSH-Patator` | `BruteForce` |
| `Bot` | `Bot` |
| `Heartbleed` (~11 rows), `Infiltration` (~36 rows), `Web Attack – Brute Force`, `Web Attack – XSS`, `Web Attack – Sql Injection` (~21 rows) | Excluded from the MVP model (`true_class` is `null`) |

Matching rules:

- Strip surrounding whitespace and compare case-insensitively. The CSVs spell it `DoS slowloris` with a lowercase "s", so exact matching against `DoS Slowloris` fails.
- In the web-attack labels, the separator may appear as an en dash, a hyphen or a broken character (`�`), depending on how the file was decoded. Treat these as the same.
- An unknown label is treated as excluded and logged as a warning. It is never silently mapped to a class.
- **Proposed:** exclude `Heartbleed` explicitly. It was not listed in #2's mapping, so without a rule it would be unmapped.

## 4. Upload format and feature schema

### 4.1 CSV format

- One network flow per row, in CICFlowMeter / CICIDS2017 format. Appendix B lists the column names.
- **Header normalisation:** strip leading and trailing whitespace from every column name *before* any matching. CICIDS2017 headers start with a space, for example `" Flow Duration"`.
- **Duplicate `Fwd Header Length`:** CICIDS2017 files contain this column twice. pandas reads the second one as `Fwd Header Length.1`. It is an exact copy and should be dropped (to confirm in #8).
- **Column order does not matter.** The backend selects and reorders columns using the feature schema (4.2).
- **Optional `Label` column:** never used for prediction. If present, the original value is returned as `true_label` and its mapped class as `true_class`. This lets the demo compare model output with the dataset label.
- **Optional identifier columns** — `Flow ID`, `Source IP`, `Source Port`, `Destination IP`, `Destination Port`, `Protocol`, `Timestamp`. These are copied into the `flow` object for display. They are used as model features only if the feature schema lists them. Note that `Destination Port` is a likely shortcut feature that may not generalise; Abhik decides.

### 4.2 Feature schema file (owned by ML, #8)

The ML pipeline exports `feature_schema.json` next to the model artifact. The backend loads it at startup and validates every upload against it, so feature names are never hard-coded in two places.

```json
{
  "schema_version": "1",
  "model_version": "rf-baseline-0.1",
  "classes": ["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "Bot"],
  "label_column": "Label",
  "features": [
    {"name": "Flow Duration", "dtype": "float64"},
    {"name": "Total Fwd Packets", "dtype": "float64"}
  ],
  "dropped_columns": ["Fwd Header Length.1"],
  "preprocessing": {
    "header_normalisation": "strip_whitespace",
    "infinity_handling": "to be documented in #8",
    "missing_value_handling": "to be documented in #8"
  }
}
```

Rules:

- The order of `features` is the model's input order.
- Uploads missing any listed feature are rejected with `422` (section 9). Extra columns are ignored.
- **Preferred:** export preprocessing and the model together as one scikit-learn `Pipeline` (`model.joblib`). Then the backend never re-implements preprocessing, and training and inference cannot drift apart.
- Default artifact location: `models/model.joblib` and `models/feature_schema.json`. The directory can be overridden with `SENTINEL_MODEL_DIR`. Model files are not committed to Git; the README explains how to produce or download them.

## 5. Endpoints

### 5.1 `GET /health`

`200 OK` (current PR #6 response):

```json
{"status": "ok", "application": "Sentinel AI"}
```

Proposed optional fields: `mode` (`"mock"` or `"model"`) and `model_loaded` (boolean). Clients treat missing values as unknown.

### 5.2 `POST /upload-csv`

Request: multipart field `file` containing a `.csv` file.

`200 OK` (current PR #6 response):

```json
{
  "status": "success",
  "filename": "sample_flows.csv",
  "total_rows": 1200,
  "total_columns": 79,
  "columns": ["Destination Port", "Flow Duration", "...", "Label"],
  "message": "CSV uploaded and validated successfully."
}
```

Proposed optional fields once the feature schema exists: `missing_features` (list of strings) and `ready_for_detection` (boolean).

### 5.3 `POST /detect`

Request: multipart field `file`. File validation and errors are the same as `/upload-csv`, plus the detection-specific errors in section 9.

`200 OK`: a `DetectionBatchResponse` (section 6.1). Appendix A has a full example.

### 5.4 `GET /model/info`

`200 OK`:

```json
{
  "contract_version": "0.1",
  "model_version": "rf-baseline-0.1",
  "detection_method": "Random Forest",
  "is_mock": false,
  "classes": ["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "Bot"],
  "features": ["Flow Duration", "Total Fwd Packets", "..."],
  "anomaly_method": "Isolation Forest",
  "trained_on": "CICIDS2017 (MachineLearningCVE CSVs)",
  "metrics": null
}
```

`metrics` is optional. When present it holds held-out test metrics from Abhik's evaluation report, such as `{"macro_f1": ..., "false_positive_rate": ...}`. It must never contain made-up values.

## 6. Response models

### 6.1 `DetectionBatchResponse`

| Field | Type | Notes |
|---|---|---|
| `contract_version` | string | `"0.1"` |
| `request_id` | string | UUID for this detection run |
| `filename` | string | Uploaded file name |
| `processed_at` | string | ISO 8601 UTC |
| `is_mock` | boolean | `true` whenever the results are not from the trained model |
| `model_version` | string | For example `"rf-baseline-0.1"`, or `"mock"` |
| `detection_method` | string | `"Random Forest"` or `"Mock"` |
| `summary` | `DetectionSummary` | Section 6.2 |
| `results` | list of `DetectionResult` | One entry per analysed row, ordered by `row_index`. Benign rows are included. |
| `row_errors` | list of `RowError` | Rows that could not be analysed. At most 100 entries; `summary.skipped_rows` has the full count. |

### 6.2 `DetectionSummary`

| Field | Type | Notes |
|---|---|---|
| `total_rows` | integer | Data rows in the file (header excluded) |
| `analyzed_rows` | integer | Rows that received a prediction |
| `skipped_rows` | integer | Rows rejected by row-level validation |
| `benign_count` | integer | Rows predicted `BENIGN` |
| `malicious_count` | integer | Rows predicted as any attack class |
| `anomaly_count` | integer | Rows with `anomaly.is_anomaly == true` |
| `by_class` | object | Count per class. All six keys are always present. |
| `by_severity` | object | Count per severity. All five keys are always present. |

These must always hold:

- `analyzed_rows + skipped_rows == total_rows`
- `benign_count + malicious_count == analyzed_rows`
- the values in `by_class` and in `by_severity` each add up to `analyzed_rows`
- `by_class["BENIGN"] == benign_count`
- `len(results) == analyzed_rows`

### 6.3 `DetectionResult`

This extends the single-record response agreed in #4 (`prediction`, `is_malicious`, `confidence`, `severity`, `detection_method`).

| Field | Type | Required | Notes |
|---|---|---|---|
| `row_index` | integer ≥ 0 | yes | 0-based data-row index in the uploaded CSV (header excluded) |
| `prediction` | class | yes | One of the six classes |
| `is_malicious` | boolean | yes | Always equals `prediction != "BENIGN"` |
| `confidence` | number 0–1 | yes | Model probability for the predicted class. Not a probability of malicious intent. |
| `confidence_band` | `"strong"`, `"moderate"` or `"weak"` | yes | Section 7.2. Uses different words from severity on purpose. |
| `severity` | `"None"`, `"Low"`, `"Medium"`, `"High"` or `"Critical"` | yes | Section 7.1. Never derived from confidence. |
| `detection_method` | string | yes | Same value as the batch |
| `anomaly` | `AnomalyResult` or `null` | yes | `null` means the anomaly detector was not run |
| `evidence` | list of `EvidenceItem` | yes (may be empty) | Up to 5 features that contributed most to this prediction |
| `flow` | `FlowInfo` or `null` | no | Identifier columns copied from the CSV |
| `true_label` | string or `null` | no | Original dataset label, if the CSV had a `Label` column |
| `true_class` | class or `null` | no | `true_label` mapped by section 3. `null` if excluded or unknown. |

### 6.4 Nested objects

**`AnomalyResult`**

| Field | Type | Notes |
|---|---|---|
| `is_anomaly` | boolean | |
| `score` | number or `null` | Higher means more anomalous. The backend negates scikit-learn's `IsolationForest.score_samples`, where lower means more anomalous. |
| `method` | string or `null` | For example `"Isolation Forest"` |

**`EvidenceItem`**

| Field | Type | Notes |
|---|---|---|
| `feature` | string | Feature name |
| `value` | number or `null` | The row's value for that feature |
| `contribution` | number or `null` | Signed SHAP value for the predicted class, or `null` if the method gives no per-row value |

**`FlowInfo`** — all fields optional: `flow_id`, `source_ip`, `source_port`, `destination_ip`, `destination_port`, `protocol`, `timestamp`.

**`RowError`** — `row_index` (integer), `column` (string or `null`), `message` (string).

## 7. Severity and confidence rules

### 7.1 Severity (proposed — confirm in #4)

Severity is a fixed, documented rule based on the predicted class and the anomaly flag. **Model confidence never raises or lowers severity.**

| Condition | Severity | Rationale |
|---|---|---|
| `BENIGN`, no anomaly | `None` | No alert |
| `BENIGN` with `anomaly.is_anomaly == true` | `Low` | Unusual traffic with no attack classification; needs review |
| `PortScan` | `Medium` | Reconnaissance; no direct impact yet, but often comes before an attack |
| `BruteForce` | `High` | Active attempt to compromise credentials (FTP/SSH) |
| `Bot` | `High` | Indicates a likely compromised host |
| `DoS` | `High` | Service availability impact |
| `DDoS` | `Critical` | Distributed availability attack with the largest impact |

An anomaly flag on an attack prediction does not change its severity. It is shown separately.

### 7.2 Confidence bands

| Band | Rule |
|---|---|
| `strong` | `confidence >= 0.90` |
| `moderate` | `0.60 <= confidence < 0.90` |
| `weak` | `confidence < 0.60` |

UI rules:

- Show confidence and severity as separate fields. Never combine them into one "risk" number.
- Label `weak` attack predictions **"Needs analyst review"**.
- Show confidence as model confidence, for example "Model confidence 0.72". Never call it the probability that an attack happened.

## 8. Anomaly representation

- Isolation Forest output appears only in the `anomaly` object. It is never a class and never changes `prediction` or `is_malicious`.
- `anomaly: null` (detector not run) is different from `anomaly.is_anomaly: false` (detector ran and found nothing).
- The dashboard styles anomaly alerts differently from classifier alerts and labels them **"Anomaly — unconfirmed"**.

## 9. Errors and limits

Error responses use FastAPI's standard body, as PR #6 already does:

```json
{"detail": "Only CSV files are accepted."}
```

FastAPI's own request validation (for example, a missing `file` field) returns `422` with `detail` as a **list** of problems. Clients must handle both a string and a list.

| Status | When | Example `detail` |
|---|---|---|
| `400` | Not a `.csv` file; empty file; unreadable CSV; no headers; blank or duplicate column names; headers but no data rows | `"The uploaded file is empty."` |
| `413` | File larger than 10 MB | `"File is too large. Maximum allowed size is 10 MB."` |
| `422` | Valid CSV, but required feature columns are missing (list up to 10), or no row could be analysed | `"Missing required feature columns: Flow Duration, Flow IAT Max"` |
| `503` | Model mode, but the model artifact is not loaded | `"Detection model is not loaded."` |
| `500` | Unexpected server error. The response never contains stack traces or internal paths. | `"Internal server error."` |

Limits:

- One `.csv` file per request, at most 10 MB. This matches `MAX_FILE_SIZE` in PR #6.
- Full CICIDS2017 day files are much larger than 10 MB, so the demo uses sample CSVs cut from them.
- Recommended client timeouts: 5 s for `/health`, 60 s for `/detect`.

## 10. Mock mode

- Until the model is integrated, `/detect` returns the same shape with `is_mock: true`, `detection_method: "Mock"` and `model_version: "mock"`.
- Whenever `is_mock` is `true`, the dashboard shows a visible **"Mock data — not live detection"** banner.
- The dashboard also has an offline mock (`SENTINEL_API_MODE=mock`) that produces exactly the same models. Frontend work does not wait for the backend.

## 11. Integration workflow

| Work | Owner | Branch | Issue |
|---|---|---|---|
| This contract | Arshan (all confirm) | `docs/api-contract` | #4 |
| FastAPI app, `/detect`, `/model/info`, schemas, tests | Sharan | `feature/backend-api` | #1, #7 |
| Dataset, label mapping, model, `feature_schema.json` | Abhik | `feature/ai-detection` | #2, #8 |
| Streamlit dashboard and API client | Arshan | `feature/security-dashboard` | #3, #9 |

Suggested merge order:

1. This contract.
2. Backend PR #6, plus mock `/detect` and `/model/info` (#7).
3. ML label mapping and feature schema (#8).
4. Dashboard and API client (#9, #3).
5. Swap the backend from mock to model output after the baseline (#2).

Every pull request targets `main` and is reviewed by someone other than its author.

Local run, from the repository root:

```bash
uvicorn src.backend.main:app --reload --port 8000
```

```bash
python -m streamlit run src/frontend/dashboard.py
```

Frontend environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `SENTINEL_API_URL` | `http://localhost:8000` | Backend base URL |
| `SENTINEL_API_MODE` | `live` | `live` calls the backend; `mock` uses offline demo data |

## 12. Notes for the backend implementation (#7)

- **Header matching:** PR #6 strips whitespace only from the column names it *reports*. Apply `df.columns = df.columns.str.strip()` before matching features.
- **Duplicate check:** pandas renames exact duplicate headers to `name.1` before the duplicate check runs. The check therefore only catches names that differ by whitespace. Test it with a real CICIDS2017 file because of the repeated `Fwd Header Length`.
- **Blank headers:** pandas renames a blank header to `Unnamed: 1`, so PR #6's "column names cannot be empty" check never fires and the file is accepted (checked against PR #6). Treat names matching `Unnamed: <n>` as blank.
- **Shifted columns:** if every data row has one more field than the header, pandas silently uses the first column as the index. Every value then lands one column to the right, and PR #6 accepts the file (checked against PR #6). Pass `index_col=False` to `pd.read_csv`.
- **Size check:** the current endpoint reads the whole upload into memory before checking its size. Check `file.size`, or read in chunks and stop after 10 MB.
- **Encoding:** some CICIDS2017 files (the Thursday web-attack file) may contain a non-UTF-8 byte in the web-attack labels. The current code returns `400` for these. Fall back to `cp1252` when UTF-8 decoding fails.
- **Severity rules:** compute severity and confidence bands exactly as in section 7. A reference implementation is in `src/frontend/api_contract.py` on `feature/security-dashboard`; move it to a shared module if both sides need it.

## 13. Decisions to confirm in #4

- [ ] Endpoint names `/detect` and `/model/info`, and keeping `/upload-csv` as validation only — Sharan
- [ ] Response fields in section 6 — all
- [ ] Label mapping, including excluding `Heartbleed` and the exact spellings — Abhik
- [ ] Ordered feature list and preprocessing in `feature_schema.json` — Abhik
- [ ] Severity table (7.1) and confidence thresholds (7.2) — all
- [ ] Error codes and limits (section 9), including the encoding fallback — Sharan
- [ ] Incident storage deferred to phase 2 — all

---

## Appendix A — Example `POST /detect` response

Four data rows: one row was skipped, and one benign row is flagged as an anomaly.

```json
{
  "contract_version": "0.1",
  "request_id": "6f1c2b9e-3d4a-4f7b-9c1e-2a5b8d7e0f13",
  "filename": "friday_ddos_sample.csv",
  "processed_at": "2026-11-06T10:15:00Z",
  "is_mock": false,
  "model_version": "rf-baseline-0.1",
  "detection_method": "Random Forest",
  "summary": {
    "total_rows": 4,
    "analyzed_rows": 3,
    "skipped_rows": 1,
    "benign_count": 2,
    "malicious_count": 1,
    "anomaly_count": 1,
    "by_class": {"BENIGN": 2, "DoS": 0, "DDoS": 1, "PortScan": 0, "BruteForce": 0, "Bot": 0},
    "by_severity": {"None": 1, "Low": 1, "Medium": 0, "High": 0, "Critical": 1}
  },
  "results": [
    {
      "row_index": 0,
      "prediction": "BENIGN",
      "is_malicious": false,
      "confidence": 0.99,
      "confidence_band": "strong",
      "severity": "None",
      "detection_method": "Random Forest",
      "anomaly": {"is_anomaly": false, "score": 0.12, "method": "Isolation Forest"},
      "evidence": [],
      "flow": null,
      "true_label": "BENIGN",
      "true_class": "BENIGN"
    },
    {
      "row_index": 1,
      "prediction": "DDoS",
      "is_malicious": true,
      "confidence": 0.96,
      "confidence_band": "strong",
      "severity": "Critical",
      "detection_method": "Random Forest",
      "anomaly": {"is_anomaly": false, "score": 0.31, "method": "Isolation Forest"},
      "evidence": [
        {"feature": "Bwd Packet Length Std", "value": 2546.4, "contribution": 0.21},
        {"feature": "Flow IAT Max", "value": 1800000.0, "contribution": 0.14}
      ],
      "flow": null,
      "true_label": "DDoS",
      "true_class": "DDoS"
    },
    {
      "row_index": 3,
      "prediction": "BENIGN",
      "is_malicious": false,
      "confidence": 0.71,
      "confidence_band": "moderate",
      "severity": "Low",
      "detection_method": "Random Forest",
      "anomaly": {"is_anomaly": true, "score": 0.78, "method": "Isolation Forest"},
      "evidence": [],
      "flow": null,
      "true_label": "BENIGN",
      "true_class": "BENIGN"
    }
  ],
  "row_errors": [
    {"row_index": 2, "column": "Flow Duration", "message": "Value 'abc' is not numeric."}
  ]
}
```

## Appendix B — CICIDS2017 column reference

The columns in the CICIDS2017 MachineLearningCVE CSVs after stripping whitespace, in file order (78 features plus `Label`). This is reference only: the authoritative model input list is `feature_schema.json` from #8.

```text
Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets,
Total Length of Fwd Packets, Total Length of Bwd Packets,
Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std,
Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std,
Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min,
Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min,
Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min,
Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags,
Fwd Header Length, Bwd Header Length, Fwd Packets/s, Bwd Packets/s,
Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance,
FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count,
URG Flag Count, CWE Flag Count, ECE Flag Count,
Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size,
Fwd Header Length.1,
Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate,
Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate,
Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes,
Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward,
Active Mean, Active Std, Active Max, Active Min,
Idle Mean, Idle Std, Idle Max, Idle Min,
Label
```

`Flow Bytes/s` and `Flow Packets/s` contain `Infinity` and empty values in the original files. Section 4.2 says how preprocessing must handle them once #8 documents it.
