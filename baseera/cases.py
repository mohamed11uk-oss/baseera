"""Case storage (SQLite) and campaign clustering from shared infrastructure / artefacts."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .phones import canonical
from .schemas import Case, Cluster, Verdict

SCHEMA = """CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY, created_at TEXT, input TEXT, kind TEXT, risk INTEGER, level TEXT,
  entity_id TEXT, registrable_domain TEXT, synthetic INTEGER DEFAULT 0, infra TEXT, verdict TEXT)"""


class CaseStore:
    """One SQLite connection shared by all request threads, serialised by a lock.

    FastAPI runs sync endpoints in a thread pool; sqlite3 connections are not safe for concurrent use even with
    check_same_thread=False (parallel requests used to fail with HTTP 500). Every DB access goes through _lock and
    rows are fully fetched before the lock is released.
    """

    def __init__(self, path: Path | str):
        self._lock = threading.RLock()
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute(SCHEMA)
        self.db.commit()

    def _fetchall(self, q: str, a: tuple | list = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self.db.execute(q, a).fetchall()

    def count(self, synthetic: bool | None = None) -> int:
        if synthetic is None:
            return self._fetchall("SELECT COUNT(*) FROM cases")[0][0]
        return self._fetchall("SELECT COUNT(*) FROM cases WHERE synthetic=?", (int(synthetic),))[0][0]

    def add_verdict(self, v: Verdict, infra: dict | None = None, synthetic: bool = False,
                    created_at: str | None = None, case_id: str | None = None) -> str:
        cid = case_id or "CASE-" + uuid.uuid4().hex[:8].upper()
        domain = v.normalized.get("registrable_domain") or v.normalized.get("domain")
        if not domain and v.sub_verdicts:
            worst = max(v.sub_verdicts, key=lambda s: s.risk)
            domain = worst.normalized.get("registrable_domain")
        infra = dict(infra or {})
        infra.setdefault("phones", [s.data.get("phone") for s in v.signals if s.id.startswith("phone_") and s.data.get("phone")])
        live = v.normalized.get("infra") or {}
        for src in ("rdap", "whois_ae"):  # .ae WHOIS fills what RDAP lacks
            d = live.get(src) or {}
            for k_in, k_out in (("nameservers", "nameservers"), ("registrar", "registrar"), ("created", "created")):
                if d.get(k_in) and not infra.get(k_out):
                    infra[k_out] = d[k_in]
        if live.get("tls"):
            infra.setdefault("ips", live["tls"].get("ips"))
        for src in ("tls", "crtsh"):  # direct handshake first, crt.sh latest certificate as fallback
            if (live.get(src) or {}).get("issuer") and not infra.get("cert_issuer"):
                infra["cert_issuer"] = live[src]["issuer"]
        sb = v.normalized.get("sandbox") or {}
        if sb.get("screenshot_phash"):
            infra.setdefault("screenshot_phash", sb["screenshot_phash"])
            infra.setdefault("screenshot_sha256", sb.get("screenshot_sha256"))
        if sb.get("form_domains"):
            infra.setdefault("form_domains", sb["form_domains"])
        if v.normalized.get("path"):
            infra.setdefault("path", v.normalized["path"])
        ent = (v.matched_entity or {}).get("id")
        v.case_id = cid
        row = (cid, created_at or datetime.now(timezone.utc).isoformat(timespec="seconds"), v.input, v.kind,
               v.risk, v.level, ent, domain, int(synthetic), json.dumps(infra, ensure_ascii=False), v.model_dump_json())
        with self._lock:
            self.db.execute("INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?)", row)
            self.db.commit()
        return cid

    def _row(self, r) -> Case:
        return Case(id=r["id"], created_at=r["created_at"], input=r["input"], kind=r["kind"], risk=r["risk"],
                    level=r["level"], entity_id=r["entity_id"], registrable_domain=r["registrable_domain"],
                    synthetic=bool(r["synthetic"]), infra=json.loads(r["infra"] or "{}"), verdict=json.loads(r["verdict"]))

    def list(self, entity: str | None = None, level: str | None = None) -> list[Case]:
        q, a = "SELECT * FROM cases WHERE 1=1", []
        if entity:
            q += " AND entity_id=?"
            a.append(entity)
        if level:
            q += " AND level=?"
            a.append(level)
        cases = [self._row(r) for r in self._fetchall(q + " ORDER BY created_at DESC", a)]
        cmap = {cid: cl.id for cl in cluster_cases(self.all()) for cid in cl.case_ids}
        for c in cases:
            c.cluster_id = cmap.get(c.id)
        return cases

    def all(self) -> list[Case]:
        return [self._row(r) for r in self._fetchall("SELECT * FROM cases ORDER BY created_at")]

    def get(self, cid: str) -> Case | None:
        rows = self._fetchall("SELECT * FROM cases WHERE id=?", (cid,))
        if not rows:
            return None
        c = self._row(rows[0])
        for cl in cluster_cases(self.all()):
            if cid in cl.case_ids:
                c.cluster_id = cl.id
        return c


# ---------------------------------------------------------------- clustering
def _path_template(p: str | None) -> str | None:
    if not p or p in ("/", ""):
        return None
    return re.sub(r"\d+", "{n}", p.lower().rstrip("/"))


def case_keys(c: Case) -> tuple[set[str], set[str]]:
    """Strong keys (one shared => same campaign) and weak keys (two shared => same campaign)."""
    i = c.infra
    strong, weak = set(), set()
    for p in i.get("phones") or []:
        strong.add("phone:" + canonical(p))
    for ip in i.get("ips") or []:
        strong.add("ip:" + ip)
    if i.get("nameservers"):
        strong.add("ns:" + ",".join(sorted(i["nameservers"])))
    if i.get("screenshot_phash"):
        strong.add("phash:" + i["screenshot_phash"])
    if i.get("registrar"):
        weak.add("registrar:" + i["registrar"].lower())
    if i.get("cert_issuer"):
        weak.add("issuer:" + i["cert_issuer"].lower())
    t = _path_template(i.get("path"))
    if t:
        weak.add("path:" + t)
    if c.entity_id:
        weak.add("target:" + c.entity_id)
    if i.get("created"):
        weak.add("created_week:" + i["created"][:4] + "-W" + datetime.fromisoformat(i["created"][:10]).strftime("%V"))
    return strong, weak


def cluster_cases(cases: list[Case]) -> list[Cluster]:
    parent = {c.id: c.id for c in cases}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    keys = {c.id: case_keys(c) for c in cases}
    shared_by_pair: dict[tuple[str, str], set[str]] = {}
    for i, a in enumerate(cases):
        for b in cases[i + 1:]:
            sa, wa = keys[a.id]
            sb, wb = keys[b.id]
            s, w = sa & sb, wa & wb
            if s or len(w) >= 2:
                parent[find(a.id)] = find(b.id)
                shared_by_pair[(a.id, b.id)] = s | w
    groups: dict[str, list[Case]] = {}
    for c in cases:
        groups.setdefault(find(c.id), []).append(c)
    out = []
    for members in groups.values():
        if len(members) < 2:
            continue
        ids = sorted(m.id for m in members)
        shared = sorted({k for (a, b), ks in shared_by_pair.items() if a in ids for k in ks})
        out.append(Cluster(
            id="CMP-" + hashlib.sha1(",".join(ids).encode()).hexdigest()[:6].upper(), case_ids=ids,
            domains=sorted({m.registrable_domain for m in members if m.registrable_domain}),
            entity_ids=sorted({m.entity_id for m in members if m.entity_id}), shared=shared,
            first_seen=min(m.created_at for m in members), last_seen=max(m.created_at for m in members),
            max_risk=max(m.risk for m in members), synthetic=all(m.synthetic for m in members)))
    return sorted(out, key=lambda c: (-len(c.case_ids), -c.max_risk))
