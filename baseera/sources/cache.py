"""Tiny JSON-file cache with per-entry expiry, shared by the optional sources. Never raises."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path


class JsonCache:
    def __init__(self, path: Path | None):
        self.path = path
        self._mem: dict[str, dict] = {}
        self._loaded = False
        self._lock = threading.Lock()

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if self.path and self.path.exists():
            try:
                self._mem.update(json.loads(self.path.read_text()))
            except Exception:  # noqa: BLE001 - corrupt cache = empty cache
                pass

    def get(self, key: str):
        with self._lock:
            self._load()
            e = self._mem.get(key)
            if e and e.get("exp", 0) > time.time():
                return e.get("v")
            return None

    def put(self, key: str, value, ttl_s: float) -> None:
        with self._lock:
            self._load()
            self._mem[key] = {"v": value, "exp": time.time() + max(0.0, ttl_s)}
            self._flush()

    def raw(self, key: str, default=None):
        """Non-expiring value (counters, metadata)."""
        with self._lock:
            self._load()
            return self._mem.get("__" + key, default)

    def set_raw(self, key: str, value) -> None:
        with self._lock:
            self._load()
            self._mem["__" + key] = value
            self._flush()

    def _flush(self) -> None:
        if not self.path:
            return
        try:
            now = time.time()
            keep = {k: v for k, v in self._mem.items() if k.startswith("__") or v.get("exp", 0) > now}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(keep))
        except Exception:  # noqa: BLE001
            pass
