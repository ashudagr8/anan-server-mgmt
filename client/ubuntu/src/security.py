import os

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_api_key(api_key: str | None = Security(API_KEY_HEADER)) -> str:
    expected_api_key = os.getenv("ANAN_CLIENT_API_KEY") or os.getenv("API_KEY")
    if not expected_api_key:
        raise HTTPException(status_code=500, detail="API key not configured on server.")
    if api_key != expected_api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return api_key
