from __future__ import annotations

import json
import mimetypes
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from dotenv import load_dotenv

from src.power_app_store import PowerAppStore, PowerAppStorePaths

APP_DIR = Path(__file__).parent
STATIC_DIR = APP_DIR / "power_app_ui"


def create_store() -> PowerAppStore:
    load_dotenv(dotenv_path=APP_DIR / ".env", override=False)
    return PowerAppStore(
        PowerAppStorePaths(
            repository_dir=Path(os.getenv("LOCAL_REPOSITORY_DIR", "/app/data/local_repository")),
            sqlite_db_path=Path(os.getenv("SQLITE_DB_PATH", "/app/data/threat_intel.db")),
            downloads_dir=Path(os.getenv("DOWNLOAD_DIR", "/app/downloads")),
        )
    )


class PowerAppPrototypeHandler(BaseHTTPRequestHandler):
    store = create_store()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path in {"/", "/index.html"}:
            self._serve_static("index.html")
            return
        if path in {"/styles.css", "/app.js"}:
            self._serve_static(path.lstrip("/"))
            return
        if path == "/api/health":
            self._json(200, self.store.health())
            return
        if path == "/api/summary":
            self._json(200, self.store.dashboard_summary())
            return
        if path == "/api/documents":
            self._json(200, self.store.list_documents())
            return
        if path.startswith("/api/documents/"):
            document_id = unquote(path.removeprefix("/api/documents/"))
            detail = self.store.get_document_detail(document_id)
            self._json(200, detail) if detail else self._json(404, {"error": "Document not found"})
            return
        if path == "/api/findings":
            self._json(200, self.store.list_findings())
            return
        if path == "/api/duplicates":
            self._json(200, self.store.list_duplicate_events())
            return
        if path.startswith("/api/findings/"):
            finding_id = unquote(path.removeprefix("/api/findings/"))
            detail = self.store.get_finding_detail(finding_id)
            self._json(200, detail) if detail else self._json(404, {"error": "Finding not found"})
            return
        if path == "/api/on-call":
            self._json(200, self.store.list_on_call_records())
            return
        if path == "/api/on-call-notes":
            self._json(200, self.store.list_on_call_notes())
            return
        if path == "/api/on-call/check":
            params = parse_qs(parsed.query)
            self._json(
                200,
                self.store.find_on_call_matches(
                    document_name=_first_query_value(params, "documentName"),
                    cve=_first_query_value(params, "cve"),
                ),
            )
            return
        if path.startswith("/api/on-call/"):
            record_id = unquote(path.removeprefix("/api/on-call/"))
            detail = self.store.get_on_call_detail(record_id)
            self._json(200, detail) if detail else self._json(404, {"error": "On-call record not found"})
            return
        if path.startswith("/pdf/"):
            self._serve_pdf(path.removeprefix("/pdf/"))
            return
        self._json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/findings/") and path.endswith("/feedback"):
            finding_id = unquote(path.removeprefix("/api/findings/").removesuffix("/feedback").strip("/"))
            payload = self._read_json_body()
            try:
                self._json(200, self.store.submit_feedback(finding_id, payload))
            except KeyError:
                self._json(404, {"error": "Finding not found"})
            return
        if path == "/api/on-call":
            payload = self._read_json_body()
            try:
                self._json(200, self.store.submit_on_call_entry(payload))
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
            return
        self._json(404, {"error": "Not found"})

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.address_string()} - {format % args}", flush=True)

    def _serve_static(self, name: str) -> None:
        path = STATIC_DIR / name
        if not path.is_file():
            self._json(404, {"error": "Static file not found"})
            return
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _serve_pdf(self, file_name: str) -> None:
        safe_name = Path(unquote(file_name)).name
        path = self.store.paths.downloads_dir / safe_name
        if not path.is_file():
            self._json(404, {"error": "PDF not found"})
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json_body(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}

    def _json(self, status: int, payload: object) -> None:
        data = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> int:
    host = os.getenv("POWER_APP_PROTOTYPE_HOST", "0.0.0.0")
    port = int(os.getenv("POWER_APP_PROTOTYPE_PORT", "8601"))
    server = HTTPServer((host, port), PowerAppPrototypeHandler)
    print(f"Power Apps-style prototype running on http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        PowerAppPrototypeHandler.store.close()
        server.server_close()
    return 0


def _first_query_value(params: dict[str, list[str]], key: str) -> str:
    values = params.get(key, [])
    return values[0] if values else ""


if __name__ == "__main__":
    raise SystemExit(main())
