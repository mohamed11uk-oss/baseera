"""Cheap API hardening: optional analyst token, request body limit, security headers.

- ANALYST_TOKEN unset (default, demo): analyst endpoints are open, as before. Set it before exposing the server.
- Token accepted as `Authorization: Bearer <t>`, `X-Analyst-Token: <t>`, or the HttpOnly session cookie set by
  POST /api/analyst/session (the cookie holds an HMAC of the token, never the token itself).
"""
from __future__ import annotations

import hashlib
import hmac

from fastapi import HTTPException, Request

COOKIE = "baseera_analyst"

# UI pages: no inline scripts, no third-party origins, no framing. (Swagger /docs keeps FastAPI's defaults.)
UI_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
          "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
# Evidence pack HTML: static document, no script at all.
EVIDENCE_CSP = ("default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; "
                "frame-ancestors 'none'")


def session_value(token: str) -> str:
    return hmac.new(token.encode(), b"baseera-analyst-session-v1", hashlib.sha256).hexdigest()


def presented_ok(request: Request, token: str) -> bool:
    auth = request.headers.get("authorization", "")
    cand = auth[7:].strip() if auth.lower().startswith("bearer ") else request.headers.get("x-analyst-token", "")
    if cand and hmac.compare_digest(cand.encode(), token.encode()):
        return True
    ck = request.cookies.get(COOKIE, "")
    return bool(ck) and hmac.compare_digest(ck.encode(), session_value(token).encode())


def analyst_guard(settings):
    """FastAPI dependency factory: 401 unless the analyst token is presented (no-op when ANALYST_TOKEN is unset)."""
    def dep(request: Request) -> None:
        tok = settings.analyst_token
        if tok and not presented_ok(request, tok):
            raise HTTPException(401, "analyst token required", headers={"WWW-Authenticate": "Bearer"})
    return dep


class BodyLimitMiddleware:
    """Reject request bodies above max_bytes with 413 (Content-Length and streamed/chunked bodies)."""

    def __init__(self, app, max_bytes: int):
        self.app, self.max = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        cl = dict(scope.get("headers") or []).get(b"content-length")
        if cl is not None and (not cl.isdigit() or int(cl) > self.max):
            return await self._reject(send)
        seen = 0
        rejected = False

        async def rcv():
            nonlocal seen, rejected
            if rejected:
                return {"type": "http.disconnect"}
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.max:  # streamed/chunked body: answer 413 now, the app only sees a disconnect
                    rejected = True
                    await self._reject(send)
                    return {"type": "http.disconnect"}
            return msg

        async def snd(msg):
            if not rejected:
                await send(msg)

        try:
            await self.app(scope, rcv, snd)
        except Exception:
            if not rejected:
                raise

    async def _reject(self, send):
        body = b'{"detail":"request body too large"}'
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


def add_security_headers(response, path: str) -> None:
    h = response.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("X-Frame-Options", "DENY")
    if path == "/" or path.startswith("/static/"):
        h.setdefault("Content-Security-Policy", UI_CSP)
