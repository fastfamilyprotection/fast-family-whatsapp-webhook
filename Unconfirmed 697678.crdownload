#!/usr/bin/env python3
"""Minimal WhatsApp Cloud API webhook receiver for Fast Family Protection.

Pure Python standard library -- no dependencies, so it runs on any
small hosted service (Render/Railway/Fly.io, a VPS, Cloudflare Workers
via a port, etc.) with just `python3 server.py`.

Endpoints
---------
GET  /webhook  Meta verification handshake:
    ?hub.mode=subscribe&hub.verify_token=<token>&hub.challenge=<value>
    Returns the challenge as plain text with HTTP 200 when the mode is
    "subscribe" and the token matches VERIFY_TOKEN; otherwise 403.
GET  /healthz  Simple liveness check (200, "ok").
POST /webhook  Meta event delivery. Verifies X-Hub-Signature-256
    (HMAC-SHA256 of the raw body, keyed by APP_SECRET) when APP_SECRET
    is set, returns 200 immediately, then appends the event to the log
    and extracts inbound messages / delivery statuses.

Storage
-------
events.jsonl  One JSON object per line: every verified POST, as received.
messages.jsonl  One JSON object per line per inbound message or status:
    {"kind": "message"|"status", "message_id": ..., "from": ...,
     "to": ..., "timestamp": ..., "text": ..., "status": ...,
     "received_at": ...}
Deduplication is by message id (in-memory set, seeded from messages.jsonl).

Configuration (environment variables -- never commit real values)
---------------------------------------------------------------
VERIFY_TOKEN  The verify token you invent and also type into Meta.
              Required; the server refuses to start without it.
APP_SECRET    Meta app secret (Gestor de Leads > Settings > Basic).
              Optional but strongly recommended: when set, POSTs with a
              missing/invalid X-Hub-Signature-256 are rejected with 403.
PORT          Listen port, default 8080. Meta requires the public URL
              to be HTTPS on port 443 with a publicly trusted certificate
              (the hosting service / reverse proxy terminates TLS).
LOG_DIR       Directory for events.jsonl / messages.jsonl, default the
              directory this file lives in.

Run locally (for testing only -- Meta cannot reach localhost):
    VERIFY_TOKEN=test-token python3 server.py
"""
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

VERIFY_TOKEN = os.environ.get("VERIFY_TOKEN", "")
APP_SECRET = os.environ.get("APP_SECRET", "")
PORT = int(os.environ.get("PORT", "8080"))
LOG_DIR = os.environ.get("LOG_DIR", os.path.dirname(os.path.abspath(__file__)))
EVENTS_LOG = os.path.join(LOG_DIR, "events.jsonl")
MESSAGES_LOG = os.path.join(LOG_DIR, "messages.jsonl")

_seen_ids = set()


def _load_seen():
    try:
        with open(MESSAGES_LOG, encoding="utf-8") as fh:
            for line in fh:
                try:
                    _seen_ids.add(json.loads(line).get("message_id"))
                except (ValueError, AttributeError):
                    continue
    except FileNotFoundError:
        pass


def _append(path, obj):
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False) + "\n")


def _verify_signature(raw_body, header):
    """Check X-Hub-Signature-256. Returns True when APP_SECRET is unset."""
    if not APP_SECRET:
        return True
    if not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(APP_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest("sha256=" + expected, header)


def _extract_events(payload):
    """Yield message/status dicts from a Meta webhook envelope."""
    now = datetime.now(timezone.utc).isoformat()
    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            value = change.get("value", {})
            metadata = value.get("metadata", {})
            for msg in value.get("messages", []):
                text = ""
                if msg.get("type") == "text":
                    text = (msg.get("text") or {}).get("body", "")
                elif msg.get("type") == "interactive":
                    inter = msg.get("interactive") or {}
                    text = ((inter.get("button_reply") or {}).get("title")
                            or (inter.get("list_reply") or {}).get("title") or "")
                yield {
                    "kind": "message",
                    "message_id": msg.get("id"),
                    "from": msg.get("from"),
                    "to": metadata.get("display_phone_number"),
                    "timestamp": msg.get("timestamp"),
                    "type": msg.get("type"),
                    "text": text,
                    "received_at": now,
                }
            for st in value.get("statuses", []):
                yield {
                    "kind": "status",
                    "message_id": st.get("id"),
                    "from": None,
                    "to": st.get("recipient_id"),
                    "timestamp": st.get("timestamp"),
                    "status": st.get("status"),
                    "text": "",
                    "errors": st.get("errors"),
                    "received_at": now,
                }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep stdout clean; logs go to files
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, body=b"", content_type="text/plain; charset=utf-8"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            return self._send(200, "ok")
        if parsed.path == "/webhook":
            q = parse_qs(parsed.query)
            mode = q.get("hub.mode", [""])[0]
            token = q.get("hub.verify_token", [""])[0]
            challenge = q.get("hub.challenge", [""])[0]
            if mode == "subscribe" and token and token == VERIFY_TOKEN:
                return self._send(200, challenge)
            return self._send(403, "Forbidden")
        return self._send(404, "Not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/webhook":
            return self._send(404, "Not found")
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if not _verify_signature(raw, self.headers.get("X-Hub-Signature-256")):
            return self._send(403, "Forbidden")
        # Acknowledge fast (Meta retries if no 200 within ~5s), then store.
        self._send(200, "EVENT_RECEIVED")
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            payload = {"_unparsed": raw.decode("utf-8", "replace")}
        _append(EVENTS_LOG, payload)
        for event in _extract_events(payload):
            mid = event.get("message_id")
            if mid and mid in _seen_ids:
                continue  # Meta delivers at-least-once; skip duplicates
            if mid:
                _seen_ids.add(mid)
            _append(MESSAGES_LOG, event)


def main():
    if not VERIFY_TOKEN:
        print("ERROR: set VERIFY_TOKEN before starting (see README.md).",
              file=sys.stderr)
        raise SystemExit(2)
    os.makedirs(LOG_DIR, exist_ok=True)
    _load_seen()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"WhatsApp webhook listening on 0.0.0.0:{PORT} "
          f"(logs in {LOG_DIR})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
