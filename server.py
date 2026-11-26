"""Local HTTP server providing a web frontend for the password generator."""

from __future__ import annotations

import argparse
import json
import mimetypes
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from password_generator import (
    PasswordConfig,
    assess_strength,
    calculate_entropy,
    generate_passwords,
    pool_size_for_config,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"


def generate_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Validate request payload and return generated passwords with strength metadata."""
    try:
        length = int(data.get("length", 16))
        count = int(data.get("count", 1))
    except (TypeError, ValueError) as exc:
        raise ValueError("Length and count must be integers.") from exc

    if count > 50:
        raise ValueError("Count cannot exceed 50 per request.")

    config = PasswordConfig(
        length=length,
        use_uppercase=bool(data.get("use_uppercase", True)),
        use_lowercase=bool(data.get("use_lowercase", True)),
        use_digits=bool(data.get("use_digits", True)),
        use_symbols=bool(data.get("use_symbols", True)),
        exclude_ambiguous=bool(data.get("exclude_ambiguous", False)),
        exclude_chars=str(data.get("exclude_chars", "")),
    )

    passwords = generate_passwords(count=count, config=config)
    pool_size = pool_size_for_config(config)
    items = []
    for pwd in passwords:
        entropy = round(calculate_entropy(pwd, pool_size=pool_size), 1)
        items.append(
            {
                "password": pwd,
                "entropy": entropy,
                "strength": assess_strength(entropy),
            }
        )
    return {"passwords": items}


class PasswordGeneratorHandler(BaseHTTPRequestHandler):
    """Serve static frontend assets and the /api/generate JSON endpoint."""

    server_version = "PasswordGeneratorHTTP/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        """Keep server logs concise."""
        return

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self, rel_path: str) -> None:
        clean = "index.html" if rel_path in ("", "/") else rel_path.lstrip("/")
        target = (STATIC_DIR / clean).resolve()
        if not target.is_relative_to(STATIC_DIR.resolve()) or not target.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return

        content_type, _ = mimetypes.guess_type(str(target))
        data = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{content_type or 'application/octet-stream'}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/api/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        self._serve_static(path)

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        if path != "/api/generate":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found."})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            data = json.loads(raw_body.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("JSON body must be an object.")
            result = generate_payload(data)
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON body."})
            return
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        self._send_json(HTTPStatus.OK, result)


def create_server(host: str = "127.0.0.1", port: int = 8000) -> ThreadingHTTPServer:
    """Create a configured ThreadingHTTPServer instance."""
    return ThreadingHTTPServer((host, port), PasswordGeneratorHandler)


def main() -> int:
    """Start the local web server."""
    parser = argparse.ArgumentParser(description="Run the password generator web UI.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    args = parser.parse_args()

    server = create_server(host=args.host, port=args.port)
    print(f"Password Generator UI running at http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
