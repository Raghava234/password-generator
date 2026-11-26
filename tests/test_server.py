"""Unit tests for the local HTTP server and API."""

from __future__ import annotations

import io
import json
import unittest
from typing import Any

from server import PasswordGeneratorHandler, generate_payload


class _FakeSocket:
    """In-memory socket replacement for testing BaseHTTPRequestHandler."""

    def __init__(self, raw_request: bytes) -> None:
        self._rfile = io.BytesIO(raw_request)
        self._wfile = io.BytesIO()

    def makefile(self, mode: str, *_args: Any, **_kwargs: Any) -> io.BytesIO:
        if "r" in mode:
            return self._rfile
        return self._wfile

    def sendall(self, data: bytes) -> None:
        self._wfile.write(data)

    @property
    def raw_response(self) -> bytes:
        return self._wfile.getvalue()


def _dispatch(raw_request: bytes) -> tuple[int, dict[str, str], bytes]:
    sock = _FakeSocket(raw_request)
    PasswordGeneratorHandler(sock, ("127.0.0.1", 12345), None)  # type: ignore[arg-type]
    raw = sock.raw_response
    head, body = raw.split(b"\r\n\r\n", 1)
    lines = head.decode("latin-1").split("\r\n")
    status_code = int(lines[0].split(" ")[1])
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip().lower()] = val.strip()
    return status_code, headers, body


class TestWebServer(unittest.TestCase):
    """Verify static frontend serving and /api/generate endpoint."""

    def test_index_and_assets_served(self) -> None:
        for path, marker in [
            ("/", "Random Password Generator"),
            ("/style.css", "--accent"),
            ("/app.js", "/api/generate"),
        ]:
            req = f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode("ascii")
            status, _headers, body = _dispatch(req)
            self.assertEqual(status, 200)
            self.assertIn(marker, body.decode("utf-8"))

    def test_health_endpoint(self) -> None:
        req = b"GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n"
        status, _headers, body = _dispatch(req)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body.decode("utf-8")), {"status": "ok"})

    def test_api_generate_success(self) -> None:
        payload = json.dumps(
            {
                "length": 18,
                "count": 3,
                "use_uppercase": True,
                "use_lowercase": True,
                "use_digits": True,
                "use_symbols": False,
                "exclude_ambiguous": True,
            }
        ).encode("utf-8")
        req = (
            f"POST /api/generate HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n\r\n"
        ).encode("ascii") + payload

        status, _headers, body = _dispatch(req)
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(len(data["passwords"]), 3)
        for item in data["passwords"]:
            self.assertEqual(len(item["password"]), 18)
            self.assertGreater(item["entropy"], 0)
            self.assertIn(item["strength"], {"Very Weak", "Weak", "Fair", "Strong", "Very Strong"})

    def test_api_generate_validation_error(self) -> None:
        payload = json.dumps(
            {
                "length": 12,
                "count": 1,
                "use_uppercase": False,
                "use_lowercase": False,
                "use_digits": False,
                "use_symbols": False,
            }
        ).encode("utf-8")
        req = (
            f"POST /api/generate HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n\r\n"
        ).encode("ascii") + payload

        status, _headers, body = _dispatch(req)
        self.assertEqual(status, 400)
        err_data = json.loads(body.decode("utf-8"))
        self.assertIn("error", err_data)

    def test_generate_payload_count_limit(self) -> None:
        with self.assertRaises(ValueError):
            generate_payload({"length": 16, "count": 51})


if __name__ == "__main__":
    unittest.main()
