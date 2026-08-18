"""Web UI API: list tools, run tools, stream logs via SSE.

Run: python webui.py  -> http://localhost:8765
"""

import asyncio
import json
import os
import time

from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

import ctfkit.modules  # noqa: F401
from ctfkit.registry import TOOLS, run_tool, list_tools
from ctfkit.logging import bus, log

app = FastAPI(title="CTF Kit", version="1.0.0")

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
_history: list[dict] = []

app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


@app.get("/")
def index() -> HTMLResponse:
    with open(os.path.join(_STATIC_DIR, "index.html"), encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "tools": len(TOOLS), "version": "1.0.0"}


@app.get("/api/tools")
def tools_list() -> dict:
    """Tool list per category for the sidebar & form builder."""
    items = list_tools()
    categories = {}
    for t in items:
        categories.setdefault(t["category"], {"label": t["category_label"], "tools": []})["tools"].append(t)
    return {"tools": items, "categories": categories, "total": len(items)}


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)) -> dict:
    """Handle file upload and return local path for tool inputs."""
    upload_dir = os.path.join(os.path.dirname(__file__), "..", "testdata", "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    clean_name = os.path.basename(file.filename or "upload.bin")
    file_path = os.path.join(upload_dir, clean_name)
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
    rel_path = f"testdata/uploads/{clean_name}"
    log.info("File uploaded: %s (%d bytes)", rel_path, len(content))
    return {"ok": True, "path": rel_path, "filename": clean_name, "size": len(content)}


@app.post("/api/run")
async def run(tool_request: dict) -> dict:
    """Run a tool. body: {name, args|arguments}. Executed in a thread pool so the UI never blocks."""
    name = tool_request.get("name", "")
    args = tool_request.get("arguments") or tool_request.get("args") or {}
    start = time.monotonic()
    result = await asyncio.get_running_loop().run_in_executor(None, run_tool, name, args)
    elapsed = (time.monotonic() - start) * 1000
    log.info("run_tool %s finished in %.0f ms", name, elapsed)
    is_error = isinstance(result, str) and result.startswith("ERROR:")
    return {
        "ok": not is_error,
        "name": name,
        "result": result,
        "error": result if is_error else None,
        "elapsed_ms": round(elapsed)
    }


@app.get("/api/logs")
async def logs_stream() -> StreamingResponse:
    """SSE: stream new log records from LogBus (lightweight polling)."""
    async def gen():
        last_count = len(bus.records)
        while True:
            records = list(bus.records)
            if len(records) != last_count:
                last_count = len(records)
                for r in records:
                    yield f"data: {json.dumps(r)}\n\n"
            else:
                yield ": ping\n\n"
            await asyncio.sleep(0.3)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/history")
def history() -> dict:
    """Run history for this session (in memory)."""
    return {"history": _history}


@app.post("/api/history")
def add_history(entry: dict) -> dict:
    _history.append({"ts": time.strftime("%H:%M:%S"), **entry})
    if len(_history) > 200:
        _history.pop(0)
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    log.info("Web UI: http://localhost:8765")
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="warning")