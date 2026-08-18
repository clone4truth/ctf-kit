"""Web UI entrypoint: python webui.py -> http://localhost:8765"""

from web.app import app  # noqa: F401

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("web.app:app", host="127.0.0.1", port=8765, log_level="warning")