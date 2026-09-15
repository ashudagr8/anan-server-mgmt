import uvicorn

from app import app
from config import build_uvicorn_run_kwargs
from execution_policy import load_execution_policy


if __name__ == "__main__":
    # Fail fast if execution policy config is invalid or unsafe.
    load_execution_policy()
    uvicorn.run(app, **build_uvicorn_run_kwargs())
