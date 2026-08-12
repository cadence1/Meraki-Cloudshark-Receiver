#!/usr/bin/env python3
"""
Minimal self-hosted receiver implementing CloudShark's documented Upload API
(https://support.qacafe.com/cloudshark/api/upload), just enough for Meraki
Dashboard's "CloudShark integration" (Network-wide > General > Packet
capture) to stream a manually-triggered packet capture here instead of to
cloudshark.org or a licensed CS Enterprise instance.

This is NOT a packet decoder/viewer - it just accepts the upload, saves the
raw capture file locally, and lets you list/download what's landed. Open the
.pcap in Wireshark yourself.

Usage:
    python server.py                  # listens on 127.0.0.1:<CLOUDSHARK_RECEIVER_PORT>

Then expose it publicly for the duration of a capture (e.g. via cloudflared -
see README.md in this folder), and in Meraki Dashboard set:
    CloudShark URL:      <public tunnel URL>
    CloudShark API key:  value of CLOUDSHARK_RECEIVER_TOKEN in ../.env
"""
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

HERE = Path(__file__).resolve().parent
# Self-contained by default (own .env, e.g. inside the Docker image); falls
# back to the parent meraki-mcp repo's .env for the original local-dev setup.
load_dotenv(HERE / ".env")
load_dotenv(HERE.parent / ".env")

CAPTURES_DIR = Path(os.getenv("CLOUDSHARK_CAPTURES_DIR", str(HERE / "captures")))
CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
INDEX_PATH = CAPTURES_DIR / "index.json"

TOKEN = os.getenv("CLOUDSHARK_RECEIVER_TOKEN")
PORT = int(os.getenv("CLOUDSHARK_RECEIVER_PORT", "8642"))
BIND_HOST = os.getenv("CLOUDSHARK_RECEIVER_BIND_HOST", "127.0.0.1")

if not TOKEN:
    sys.exit("CLOUDSHARK_RECEIVER_TOKEN not set in .env - refusing to start with no auth token")

import uvicorn  # noqa: E402
from starlette.applications import Starlette  # noqa: E402
from starlette.requests import Request  # noqa: E402
from starlette.responses import JSONResponse, HTMLResponse, FileResponse, PlainTextResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402


def _load_index():
    if INDEX_PATH.exists():
        return json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    return {}


def _save_index(idx):
    INDEX_PATH.write_text(json.dumps(idx, indent=2), encoding="utf-8")


def _check_token(request_token):
    return request_token == TOKEN


async def upload(request: Request):
    """Handles both POST (multipart 'file' field) and PUT (raw body) per the
    CloudShark upload API spec."""
    token = request.path_params["token"]
    if not _check_token(token):
        return JSONResponse({"status": 401, "exceptions": ["invalid API token"]}, status_code=401)

    capture_id = uuid.uuid4().hex[:12]
    filename = request.query_params.get("filename")
    comments = request.query_params.get("comments")
    tags = request.query_params.get("additional_tags")

    if request.method == "PUT":
        body = await request.body()
        if not body:
            return JSONResponse({"status": 400, "exceptions": ["empty request body"]}, status_code=400)
        filename = filename or f"capture-{capture_id}.pcap"
        dest = CAPTURES_DIR / f"{capture_id}_{filename}"
        dest.write_bytes(body)
    else:  # POST, multipart/form-data
        form = await request.form()
        upload_field = form.get("file")
        if upload_field is None:
            return JSONResponse({"status": 400, "exceptions": ["missing 'file' field"]}, status_code=400)
        filename = filename or form.get("filename") or getattr(upload_field, "filename", None) or f"capture-{capture_id}.pcap"
        comments = comments or form.get("comments")
        tags = tags or form.get("additional_tags")
        dest = CAPTURES_DIR / f"{capture_id}_{filename}"
        content = await upload_field.read()
        dest.write_bytes(content)

    idx = _load_index()
    idx[capture_id] = {
        "filename": filename,
        "path": dest.name,
        "comments": comments,
        "tags": tags,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "size_bytes": dest.stat().st_size,
        "source_ip": request.client.host if request.client else None,
    }
    _save_index(idx)
    print(f"[upload] {filename} ({dest.stat().st_size:,} bytes) -> {capture_id}")

    return JSONResponse({"filename": filename, "id": capture_id})


async def list_captures(request: Request):
    idx = _load_index()
    rows = "".join(
        f'<tr><td><a href="/captures/{cid}">{cid}</a></td><td>{v["filename"]}</td>'
        f'<td>{v["size_bytes"]:,} B</td><td>{v["uploaded_at"]}</td><td>{v.get("source_ip") or ""}</td></tr>'
        for cid, v in sorted(idx.items(), key=lambda kv: kv[1]["uploaded_at"], reverse=True)
    )
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>Captures</title>
    <style>body{{font-family:sans-serif;max-width:900px;margin:32px auto}}
    table{{border-collapse:collapse;width:100%}} td,th{{padding:6px 10px;border-bottom:1px solid #ddd;text-align:left}}</style>
    </head><body><h1>Received packet captures</h1>
    <table><tr><th>ID</th><th>Filename</th><th>Size</th><th>Uploaded (UTC)</th><th>From</th></tr>{rows}</table>
    </body></html>"""
    return HTMLResponse(html)


async def get_capture(request: Request):
    capture_id = request.path_params["capture_id"]
    idx = _load_index()
    entry = idx.get(capture_id)
    if not entry:
        return PlainTextResponse("not found", status_code=404)
    return FileResponse(CAPTURES_DIR / entry["path"], filename=entry["filename"])


async def health(request: Request):
    return PlainTextResponse("ok")


app = Starlette(routes=[
    Route("/api/v1/{token}/upload", upload, methods=["POST", "PUT"]),
    Route("/captures", list_captures, methods=["GET"]),
    Route("/captures/{capture_id}", get_capture, methods=["GET"]),
    Route("/", health, methods=["GET"]),
])


if __name__ == "__main__":
    print(f"CloudShark-compatible receiver listening on http://{BIND_HOST}:{PORT}")
    print(f"Upload endpoint (what goes in Meraki's CloudShark URL + API key fields):")
    print(f"  base URL for Dashboard's 'CloudShark URL' field: <your public hostname>")
    print(f"  API key for Dashboard's 'CloudShark API key' field: {TOKEN}")
    print(f"Captures list: http://{BIND_HOST}:{PORT}/captures")
    uvicorn.run(app, host=BIND_HOST, port=PORT)
