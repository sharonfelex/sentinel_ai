"""HTTP client the Streamlit dashboard uses to call the Sentinel AI backend.

All HTTP logic lives here, so UI code never builds requests or parses raw JSON.
Responses are validated against the API contract
(``docs/architecture/api-contract.md``, models in ``api_contract.py``).

Configuration (environment variables):

* ``SENTINEL_API_URL``  - backend base URL, default ``http://localhost:8000``
* ``SENTINEL_API_MODE`` - ``live`` (default) calls the backend; ``mock`` uses
  offline demo data that is always marked ``is_mock=True``

Typical Streamlit usage::

    import streamlit as st
    from src.frontend.api_client import ApiError, ApiUnavailableError, get_client

    @st.cache_resource
    def api():
        return get_client()

    try:
        batch = api().detect_csv(upload.name, upload.getvalue())
    except ApiUnavailableError:
        st.error("The detection API is not reachable. Is the backend running?")
    except ApiError as exc:
        st.error(str(exc))
"""

from __future__ import annotations

import os
from typing import Protocol, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from src.frontend.api_contract import (
    DetectionBatchResponse,
    HealthResponse,
    ModelInfo,
    UploadValidationResponse,
)

DEFAULT_API_URL = "http://localhost:8000"
DEFAULT_TIMEOUT_SECONDS = 60.0
HEALTH_TIMEOUT_SECONDS = 5.0

ModelT = TypeVar("ModelT", bound=BaseModel)


class ApiError(Exception):
    """Base class for every error the dashboard should show to the user."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class ApiUnavailableError(ApiError):
    """The backend could not be reached or did not answer in time."""


class ApiRequestError(ApiError):
    """The backend rejected the request (4xx), for example an invalid CSV."""


class ApiServerError(ApiError):
    """The backend failed while handling the request (5xx)."""


class ContractError(ApiError):
    """The backend answered, but the response does not match the API contract."""


class SentinelApi(Protocol):
    """Interface shared by the live client and the offline mock."""

    is_mock: bool

    def health(self) -> HealthResponse: ...

    def validate_csv(self, filename: str, content: bytes) -> UploadValidationResponse: ...

    def detect_csv(self, filename: str, content: bytes) -> DetectionBatchResponse: ...

    def model_info(self) -> ModelInfo: ...


class SentinelApiClient:
    """Client for the FastAPI backend."""

    is_mock = False

    def __init__(
        self,
        base_url: str | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.base_url = (
            base_url or os.getenv("SENTINEL_API_URL") or DEFAULT_API_URL
        ).rstrip("/")
        self._http = http_client or httpx.Client(base_url=self.base_url, timeout=timeout)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "SentinelApiClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # --- Endpoints (contract section 5) ------------------------------------

    def health(self) -> HealthResponse:
        return self._request(
            "GET", "/health", HealthResponse, timeout=HEALTH_TIMEOUT_SECONDS
        )

    def validate_csv(self, filename: str, content: bytes) -> UploadValidationResponse:
        """Check a CSV with ``POST /upload-csv`` without running detection."""
        return self._request(
            "POST", "/upload-csv", UploadValidationResponse, files=_csv_upload(filename, content)
        )

    def detect_csv(self, filename: str, content: bytes) -> DetectionBatchResponse:
        """Run detection on a CSV with ``POST /detect``."""
        return self._request(
            "POST", "/detect", DetectionBatchResponse, files=_csv_upload(filename, content)
        )

    def model_info(self) -> ModelInfo:
        return self._request("GET", "/model/info", ModelInfo)

    # --- Internals ---------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        model: type[ModelT],
        *,
        timeout: float | None = None,
        files: dict | None = None,
    ) -> ModelT:
        kwargs: dict = {}
        if files is not None:
            kwargs["files"] = files
        if timeout is not None:
            kwargs["timeout"] = timeout

        try:
            response = self._http.request(method, path, **kwargs)
        except httpx.TimeoutException as exc:
            raise ApiUnavailableError(
                f"The Sentinel API at {self.base_url} did not respond in time."
            ) from exc
        except httpx.TransportError as exc:
            raise ApiUnavailableError(
                f"Cannot reach the Sentinel API at {self.base_url}. Is the backend running?"
            ) from exc

        if response.status_code == 404:
            raise ApiRequestError(
                f"The endpoint {path} is not available on this backend yet.",
                status_code=404,
            )
        if response.status_code >= 500:
            raise ApiServerError(_error_message(response), status_code=response.status_code)
        if response.status_code >= 400:
            raise ApiRequestError(_error_message(response), status_code=response.status_code)

        try:
            payload = response.json()
        except ValueError as exc:
            raise ContractError(
                f"The response from {path} was not valid JSON.",
                status_code=response.status_code,
            ) from exc

        try:
            return model.model_validate(payload)
        except ValidationError as exc:
            raise ContractError(
                f"The response from {path} does not match the API contract "
                f"({exc.error_count()} problem(s)): {_first_problem(exc)}",
                status_code=response.status_code,
            ) from exc


def get_client() -> SentinelApi:
    """Return the live client or the offline mock, based on ``SENTINEL_API_MODE``."""
    mode = os.getenv("SENTINEL_API_MODE", "live").strip().lower()
    if mode == "live":
        return SentinelApiClient()
    if mode == "mock":
        from src.frontend.mock_api import MockSentinelApi

        return MockSentinelApi()
    raise ValueError(f"SENTINEL_API_MODE must be 'live' or 'mock', not {mode!r}")


def _csv_upload(filename: str, content: bytes) -> dict:
    return {"file": (filename, content, "text/csv")}


def _error_message(response: httpx.Response) -> str:
    """Turn a FastAPI error body into a message that can be shown in the UI."""
    try:
        detail = response.json().get("detail")
    except (ValueError, AttributeError):
        detail = None

    if isinstance(detail, str) and detail:
        return detail
    if isinstance(detail, list) and detail:
        # FastAPI request-validation errors: [{"loc": [...], "msg": "..."}, ...]
        parts = []
        for item in detail[:3]:
            if isinstance(item, dict):
                location = ".".join(str(p) for p in item.get("loc", []) if p != "body")
                message = item.get("msg", "invalid value")
                parts.append(f"{location}: {message}" if location else message)
            else:
                parts.append(str(item))
        return "; ".join(parts)
    return f"Request failed with HTTP {response.status_code}."


def _first_problem(exc: ValidationError) -> str:
    error = exc.errors()[0]
    location = ".".join(str(p) for p in error.get("loc", ()))
    return f"{location}: {error.get('msg')}" if location else str(error.get("msg"))
