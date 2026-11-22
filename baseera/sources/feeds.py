"""PhishTank + OpenPhish blocklist feeds imported into a local SQLite DB.

- PhishTank "verified online" JSON database (app key from PHISHTANK_APP_KEY, optional). Cadence: hourly.
- OpenPhish community feed (plain text, one URL per line, no key). Cadence: 12 hours.

Refresh runs from the CLI (`python -m baseera feeds refresh`), never inside /api/analyze. Lookups (match_exact /
match_host) are local SQLite queries, so they also work in BASEERA_MODE=offline once the DB has been filled.
Feed content is UNTRUSTED data: it is parsed as JSON/text only, URLs are never fetched.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

PHISHTANK = "phishtank"
OPENPHISH = "openphish"
SOURCES = {
    PHISHTANK: {"cadence_s": 3600, "label": "PhishTank (verified online)"},
    OPENPHISH: {"cadence_s": 12 * 3600, "label": "OpenPhish community feed"},
}
OPENPHISH_URL = "https://openphish.com/feed.txt"
MAX_BYTES = 256 * 1024 * 1024  # hard cap on a downloaded feed (decompressed), protects against huge/bomb responses
USER_AGENT = "baseera-feeds/0.1 (hackathon prototype)"


def phishtank_url(app_key: str | None) -> str:
    if app_key:
        return f"https://data.phishtank.com/data/{app_key}/online-valid.json"
    return "https://data.phishtank.com/data/online-valid.json"


def _utc(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts if ts is not None else time.time(), timezone.utc).isoformat(timespec="seconds")


def _strip_www(h: str) -> str:
    return h[4:] if h.startswith("www.") else h


def url_key(url: str) -> tuple[str, str] | None:
    """(key, host) used for exact matching: scheme-less, lower-case host, no default port/fragment/trailing slash."""
    u = url.strip()
    if not u:
        return None
    if "://" not in u:
        u = "http://" + u
    try:
        p = urlsplit(u)
        host = (p.hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if not host:
        return None
    host = _strip_www(host)
    port = p.port if p.port not in (None, 80, 443) else None
    path = p.path.rstrip("/")
    key = host + (f":{port}" if port else "") + path + (f"?{p.query}" if p.query else "")
    return key, host


def parse_phishtank(data: bytes | str) -> list[dict]:
    rows = json.loads(data)
    out = []
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict) or not isinstance(r.get("url"), str):
            continue
        if str(r.get("verified", "yes")).lower() not in ("yes", "true", "1"):
            continue
        tgt = r.get("target")
        out.append({"url": r["url"][:2048], "target": tgt if isinstance(tgt, str) and tgt != "Other" else None,
                    "first_seen": r.get("submission_time") if isinstance(r.get("submission_time"), str) else None})
    return out


def parse_openphish(text: bytes | str) -> list[dict]:
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    return [{"url": ln.strip()[:2048], "target": None, "first_seen": None}
            for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


class FeedStore:
    def __init__(self, path: Path | str):
        self.path = str(path)
        self._lock = threading.Lock()
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS feed_entries(
              source TEXT NOT NULL, url TEXT NOT NULL, url_key TEXT NOT NULL, host TEXT NOT NULL,
              target TEXT, first_seen TEXT, last_seen TEXT, PRIMARY KEY(source, url_key));
            CREATE INDEX IF NOT EXISTS ix_feed_key ON feed_entries(url_key);
            CREATE INDEX IF NOT EXISTS ix_feed_host ON feed_entries(host);
            CREATE TABLE IF NOT EXISTS feed_meta(
              source TEXT PRIMARY KEY, last_attempt REAL, last_success REAL, count INTEGER, status TEXT);
        """)

    # ------------------------------------------------------------------ write
    def import_rows(self, source: str, rows: list[dict], now: float | None = None) -> int:
        """Replace the snapshot of `source` with `rows`, keeping first_seen of URLs that were already listed."""
        now = now if now is not None else time.time()
        stamp = _utc(now)
        with self._lock, self.db:
            for r in rows:
                k = url_key(r["url"])
                if not k:
                    continue
                self.db.execute(
                    "INSERT INTO feed_entries(source,url,url_key,host,target,first_seen,last_seen) VALUES(?,?,?,?,?,?,?) "
                    "ON CONFLICT(source,url_key) DO UPDATE SET last_seen=excluded.last_seen, "
                    "target=COALESCE(excluded.target, feed_entries.target)",
                    (source, r["url"], k[0], k[1], r.get("target"), r.get("first_seen") or stamp, stamp))
            self.db.execute("DELETE FROM feed_entries WHERE source=? AND last_seen<>?", (source, stamp))
            n = self.db.execute("SELECT COUNT(*) FROM feed_entries WHERE source=?", (source,)).fetchone()[0]
            self.db.execute("INSERT INTO feed_meta(source,last_attempt,last_success,count,status) VALUES(?,?,?,?,?) "
                            "ON CONFLICT(source) DO UPDATE SET last_attempt=excluded.last_attempt, "
                            "last_success=excluded.last_success, count=excluded.count, status=excluded.status",
                            (source, now, now, n, "ok"))
        return n

    def _mark_attempt(self, source: str, status: str, now: float) -> None:
        with self._lock, self.db:
            self.db.execute("INSERT INTO feed_meta(source,last_attempt,count,status) VALUES(?,?,0,?) "
                            "ON CONFLICT(source) DO UPDATE SET last_attempt=excluded.last_attempt, status=excluded.status",
                            (source, now, status))

    # ------------------------------------------------------------------- read
    def _rows(self, sql: str, args: tuple) -> list[dict]:
        with self._lock:
            cur = self.db.execute(sql, args)
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]

    def match_exact(self, url: str) -> list[dict]:
        k = url_key(url)
        if not k:
            return []
        return self._rows("SELECT source,url,host,target,first_seen FROM feed_entries WHERE url_key=? ORDER BY source",
                          (k[0],))

    def match_host(self, host: str, limit: int = 5) -> list[dict]:
        h = _strip_www(host.lower().rstrip("."))
        return self._rows("SELECT source,url,host,target,first_seen FROM feed_entries WHERE host=? "
                          "ORDER BY target IS NULL, first_seen LIMIT ?", (h, limit))

    def counts(self) -> dict[str, int]:
        return {r["source"]: r["n"] for r in
                self._rows("SELECT source, COUNT(*) AS n FROM feed_entries GROUP BY source", ())}

    def meta(self) -> dict[str, dict]:
        out = {}
        for r in self._rows("SELECT * FROM feed_meta", ()):
            out[r["source"]] = {"count": r["count"] or 0, "status": r["status"],
                                "last_attempt": _utc(r["last_attempt"]) if r["last_attempt"] else None,
                                "last_success": _utc(r["last_success"]) if r["last_success"] else None}
        return out

    def due(self, source: str, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        r = self._rows("SELECT last_attempt FROM feed_meta WHERE source=?", (source,))
        last = r[0]["last_attempt"] if r else None
        return last is None or now - last >= SOURCES[source]["cadence_s"]

    # ---------------------------------------------------------------- refresh
    def refresh(self, source: str, *, app_key: str | None = None, client=None, force: bool = False,
                timeout_s: float = 60.0, now: float | None = None) -> dict:
        """Download + import one feed if its cadence allows (or force). Never raises; returns a status dict."""
        now = now if now is not None else time.time()
        if not force and not self.due(source, now):
            m = self.meta().get(source, {})
            return {"source": source, "status": "skipped (cadence)", "count": m.get("count", 0),
                    "last_attempt": m.get("last_attempt")}
        url = phishtank_url(app_key) if source == PHISHTANK else OPENPHISH_URL
        own = client is None
        try:
            if own:
                client = _default_client(timeout_s)
            body = _download(client, url)
            rows = parse_phishtank(body) if source == PHISHTANK else parse_openphish(body)
            n = self.import_rows(source, rows, now)
            return {"source": source, "status": "ok", "count": n}
        except Exception as e:  # noqa: BLE001 - fail soft, keep the previous snapshot
            msg = f"error: {type(e).__name__}"
            if isinstance(e, _HTTPError):
                msg = f"error: HTTP {e.status}"
            self._mark_attempt(source, msg, now)
            return {"source": source, "status": msg, "count": self.counts().get(source, 0)}
        finally:
            if own and client is not None:
                client.close()


class _HTTPError(Exception):
    def __init__(self, status: int):
        super().__init__(status)
        self.status = status


def _default_client(timeout_s: float):
    import httpx

    from ..normalize import ssrf_check

    def guard(request):  # SSRF guard on every hop (the feed hosts redirect to CDNs)
        ssrf_check(request.url.host)

    return httpx.Client(timeout=timeout_s, follow_redirects=True, headers={"User-Agent": USER_AGENT},
                        event_hooks={"request": [guard]})


def _download(client, url: str) -> bytes:
    with client.stream("GET", url) as r:
        if r.status_code != 200:
            raise _HTTPError(r.status_code)
        buf = bytearray()
        for chunk in r.iter_bytes():
            buf += chunk
            if len(buf) > MAX_BYTES:
                raise ValueError("feed larger than MAX_BYTES")
        return bytes(buf)


def open_store(settings) -> FeedStore | None:
    """The feed DB if the source is enabled and the DB file exists (lookups never create it implicitly)."""
    if not settings.source_feeds or not Path(settings.feeds_db).exists():
        return None
    try:
        return FeedStore(settings.feeds_db)
    except Exception:  # noqa: BLE001
        return None
