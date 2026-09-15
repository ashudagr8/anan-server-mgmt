import os


def build_uvicorn_run_kwargs() -> dict[str, object]:
    host = os.getenv("ANAN_CLIENT_HOST", "0.0.0.0")
    port = int(os.getenv("ANAN_CLIENT_PORT", "8000"))
    run_kwargs: dict[str, object] = {"host": host, "port": port}

    cert_file = os.getenv("ANAN_CLIENT_HTTPS_CERT")
    key_file = os.getenv("ANAN_CLIENT_HTTPS_KEY")
    if cert_file and key_file:
        run_kwargs["ssl_certfile"] = cert_file
        run_kwargs["ssl_keyfile"] = key_file

    return run_kwargs
