from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .config import load_settings
from .database import init_db, list_scans, save_scan
from .scanner import scan_tls_target

settings = load_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db(settings.database_path)
    yield


app = FastAPI(
    title="Cryptographic Network Forensics Engine",
    version="0.1.0",
    description="Authorized, bounded TLS inventory scanner. Stage 1 does not exploit targets.",
    lifespan=lifespan,
)


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)


@app.get("/health")
def health():
    return {"status": "ok", "service": "cryptographic-network-forensics-engine", "stage": 1}


@app.post("/api/scan")
def create_scan(request: ScanRequest):
    try:
        result = scan_tls_target(request.target, request.port, settings)
        save_scan(settings.database_path, result)
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=502, detail=f"Network/TLS scan failed: {exc}") from exc


@app.get("/api/scans")
def get_scans(limit: int = 50):
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 200")
    return {"items": list_scans(settings.database_path, limit)}
