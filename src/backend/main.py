from fastapi import FastAPI

app = FastAPI(
    title="Sentinel AI API",
    description="Backend API for network intrusion detection and threat analysis.",
    version="0.1.0",
)


@app.get("/", tags=["General"])
def root() -> dict[str, str]:
    """Return basic API information."""
    return {
        "application": "Sentinel AI",
        "message": "Network intrusion detection API",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
def health_check() -> dict[str, str]:
    """Health check used to verify that the API is running."""
    return {
        "status": "ok",
        "application": "Sentinel AI",
    }
