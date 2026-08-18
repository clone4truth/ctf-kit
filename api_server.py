"""Headless REST API Server for CTF Kit (HexStrike-style Architecture).

Interactive OpenAPI / Swagger Documentation:
    http://127.0.0.1:8765/docs

Run:
    python api_server.py
"""

import asyncio
import json
import os
import time

from fastapi import FastAPI, UploadFile, File, Query, HTTPException
from fastapi.responses import JSONResponse

import ctfkit.modules  # noqa: F401
from ctfkit.registry import TOOLS, run_tool, list_tools
from ctfkit.logging import log

app = FastAPI(
    title="CTF Kit — Headless Security & CTF Engine",
    description="HexStrike-style Headless REST API & MCP engine providing 90 specialized cybersecurity operations.",
    version="2.5.0",
    docs_url="/docs",
    redoc_url="/redoc"
)


@app.get("/api/health", tags=["Status"])
def health() -> dict:
    """Check API server health and total registered tools count."""
    return {"status": "ok", "tools": len(TOOLS), "version": "2.5.0"}


@app.get("/api/tools", tags=["Tools"])
def tools_list(category: str | None = Query(None, description="Optional category filter")) -> dict:
    """Retrieve full catalog of registered security & CTF tools with parameter schemas."""
    items = list_tools()
    if category:
        items = [t for t in items if t["category"].lower() == category.lower()]
    categories = {}
    for t in items:
        categories.setdefault(t["category"], {"label": t["category_label"], "tools": []})["tools"].append(t)
    return {"total": len(items), "tools": items, "categories": categories}


@app.get("/api/tools/{name}", tags=["Tools"])
def get_tool_info(name: str) -> dict:
    """Get metadata and parameter specification for a single tool."""
    tool = TOOLS.get(name)
    if not tool:
        raise HTTPException(status_code=404, detail=f"Tool '{name}' not found.")
    return {
        "name": tool.name,
        "category": tool.category,
        "summary": tool.summary,
        "parameters": [
            {
                "name": p.name,
                "type": p.type,
                "required": p.required,
                "default": p.default,
                "doc": p.doc
            }
            for p in tool.parameters
        ]
    }


@app.post("/api/run", tags=["Execution"])
async def run_tool_endpoint(tool_request: dict) -> dict:
    """Execute a tool with parameters asynchronously in thread pool.
    
    Request Body:
        {
            "name": "caesar",
            "arguments": {"text": "Spwwz Hzpwwoi", "shift": -1}
        }
    """
    name = tool_request.get("name", "")
    args = tool_request.get("arguments") or tool_request.get("args") or {}

    if not name or name not in TOOLS:
        raise HTTPException(status_code=404, detail=f"Tool '{name}' not found.")

    start = time.monotonic()
    try:
        result = await asyncio.get_running_loop().run_in_executor(None, run_tool, name, args)
        elapsed = (time.monotonic() - start) * 1000
        is_error = isinstance(result, str) and result.startswith("ERROR:")
        return {
            "ok": not is_error,
            "name": name,
            "result": result,
            "error": result if is_error else None,
            "elapsed_ms": round(elapsed, 2)
        }
    except Exception as ex:
        elapsed = (time.monotonic() - start) * 1000
        return {
            "ok": False,
            "name": name,
            "result": f"ERROR: {ex}",
            "error": str(ex),
            "elapsed_ms": round(elapsed, 2)
        }


@app.post("/api/upload", tags=["Files"])
async def upload_file(file: UploadFile = File(...)) -> dict:
    """Upload a challenge binary or capture file for processing by tools."""
    upload_dir = os.path.join(os.path.dirname(__file__), "testdata", "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    clean_name = os.path.basename(file.filename or "upload.bin")
    file_path = os.path.join(upload_dir, clean_name)
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
    rel_path = f"testdata/uploads/{clean_name}"
    return {"ok": True, "path": rel_path, "filename": clean_name, "size": len(content)}


if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("⚡ CTF Kit — Headless REST API Engine")
    print("Swagger UI Documentation: http://127.0.0.1:8765/docs")
    print("=" * 60)
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")
