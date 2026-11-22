"""Runtime configuration from environment variables (no secrets in code).

A local `.env` file (git-ignored) is loaded once at import time by a tiny built-in loader: it only fills variables that
are not already set in the real environment, never prints values, and can be disabled with BASEERA_DOTENV=off
(the test suite does this). BASEERA_ENV_FILE points at another file.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"


def load_dotenv(path: Path | str | None = None, override: bool = False) -> list[str]:
    """Load KEY=VALUE lines from a .env file into os.environ. Returns the variable NAMES set (never the values).

    Supports comments, blank lines, an optional `export ` prefix, single/double quotes and trailing ` # comments` on
    unquoted values. Missing file => no-op. Existing environment variables win unless override=True.
    """
    p = Path(path) if path else Path(os.getenv("BASEERA_ENV_FILE", str(ROOT / ".env")))
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    names = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, sep, val = line.partition("=")
        key = key.strip()
        if not sep or not key.replace("_", "").isalnum():
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        elif val.startswith("#"):
            val = ""
        else:
            val = val.split(" #", 1)[0].split("\t#", 1)[0].strip()
        if override or key not in os.environ:
            os.environ[key] = val
            names.append(key)
    return names


def serpapi_key_from_env() -> str | None:
    """SerpAPI key: SERPAPI_KEY, or SERPAPI_API_KEY (the name SerpAPI's own docs and clients use)."""
    return os.getenv("SERPAPI_KEY") or os.getenv("SERPAPI_API_KEY") or None


if os.getenv("BASEERA_DOTENV", "on").lower() not in ("0", "off", "false", "no"):
    load_dotenv()


def _flag(name: str, default: str = "on") -> bool:
    return os.getenv(name, default).lower() in ("1", "on", "true", "yes")


@dataclass
class Settings:
    # offline: never touch the network (tests, eval, demo replay). live: RDAP/TLS/redirect lookups.
    mode: str = field(default_factory=lambda: os.getenv("BASEERA_MODE", "live"))
    timeout_s: float = field(default_factory=lambda: float(os.getenv("BASEERA_TIMEOUT", "4")))
    db_path: Path = field(default_factory=lambda: Path(os.getenv("BASEERA_DB", str(DATA / "runtime" / "baseera.db"))))
    seed_demo: bool = field(default_factory=lambda: _flag("BASEERA_SEED_DEMO", "on"))
    # Optional external sources (all fail soft, all off unless a key is present)
    serpapi_key: str | None = field(default_factory=serpapi_key_from_env)  # SERPAPI_KEY or SERPAPI_API_KEY
    gsb_api_key: str | None = field(default_factory=lambda: os.getenv("GSB_API_KEY") or None)
    source_rdap: bool = field(default_factory=lambda: _flag("SOURCE_RDAP"))
    source_tls: bool = field(default_factory=lambda: _flag("SOURCE_TLS"))
    source_redirects: bool = field(default_factory=lambda: _flag("SOURCE_REDIRECTS"))
    # Threat-intel feeds (PhishTank + OpenPhish) imported into a local SQLite DB by `python -m baseera feeds refresh`.
    # Lookups are local (no network), so they also work in offline mode once the DB exists.
    source_feeds: bool = field(default_factory=lambda: _flag("SOURCE_FEEDS"))
    feeds_db: Path = field(default_factory=lambda: Path(os.getenv("BASEERA_FEEDS_DB", str(DATA / "runtime" / "feeds.db"))))
    phishtank_app_key: str | None = field(default_factory=lambda: os.getenv("PHISHTANK_APP_KEY") or None)
    feeds_download_timeout_s: float = field(default_factory=lambda: float(os.getenv("FEEDS_DOWNLOAD_TIMEOUT", "60")))
    # crt.sh certificate transparency (domain-age proxy + first cert date). Often overloaded: 6s, 2 retries.
    source_crtsh: bool = field(default_factory=lambda: _flag("SOURCE_CRTSH"))
    crtsh_timeout_s: float = field(default_factory=lambda: float(os.getenv("CRTSH_TIMEOUT", "6")))
    crtsh_retries: int = field(default_factory=lambda: int(os.getenv("CRTSH_RETRIES", "2")))
    # .ae WHOIS (whois.aeda.net.ae:43), tried before crt.sh for .ae domains. Port 43 is often blocked: fail soft.
    source_whois_ae: bool = field(default_factory=lambda: _flag("SOURCE_WHOIS_AE"))
    # Google Safe Browsing v4 Lookup API: off unless GSB_API_KEY is set (and SOURCE_GSB is not off).
    source_gsb: bool = field(default_factory=lambda: _flag("SOURCE_GSB"))
    gsb_daily_limit: int = field(default_factory=lambda: int(os.getenv("GSB_DAILY_LIMIT", "10000")))
    # Optional key-gated sources, all OFF by default (SOURCE_*=on AND the key must be set; live mode only).
    # URLhaus (abuse.ch): malware URL/host lookup in the analyze path. Header Auth-Key.
    urlhaus_auth_key: str | None = field(default_factory=lambda: os.getenv("URLHAUS_AUTH_KEY") or None)
    source_urlhaus: bool = field(default_factory=lambda: _flag("SOURCE_URLHAUS", "off"))
    # urlscan.io: read existing scans only (informational, weight 0). Header API-Key.
    urlscan_api_key: str | None = field(default_factory=lambda: os.getenv("URLSCAN_API_KEY") or None)
    source_urlscan: bool = field(default_factory=lambda: _flag("SOURCE_URLSCAN", "off"))
    # VirusTotal: manual deep check endpoint only (never in /api/analyze). Free tier: 4 requests/min.
    vt_api_key: str | None = field(default_factory=lambda: os.getenv("VT_API_KEY") or None)
    source_vt: bool = field(default_factory=lambda: _flag("SOURCE_VT", "off"))
    vt_per_minute: int = field(default_factory=lambda: int(os.getenv("VT_PER_MINUTE", "4")))
    # Anthropic (vision, grey-zone pages): key read here but no caller yet (Prompt 0.3 leaves it unwired).
    anthropic_api_key: str | None = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY") or None)
    cache_dir: Path = field(default_factory=lambda: Path(os.getenv("BASEERA_CACHE_DIR", str(DATA / "runtime"))))
    # Deep scan (headless Chrome sandbox): off | request (only when the API call sets deep=true) | on (every URL).
    source_sandbox: str = field(default_factory=lambda: os.getenv("SOURCE_SANDBOX", "request").lower())
    screenshot_dir: Path = field(default_factory=lambda: Path(os.getenv(
        "BASEERA_SCREENSHOT_DIR", str(Path(os.getenv("BASEERA_CACHE_DIR", str(DATA / "runtime"))) / "screenshots"))))

    # Security (all optional). ANALYST_TOKEN set => /api/cases*, /api/clusters and evidence packs need it.
    analyst_token: str | None = field(default_factory=lambda: os.getenv("ANALYST_TOKEN") or None)
    max_body_bytes: int = field(default_factory=lambda: int(os.getenv("BASEERA_MAX_BODY_BYTES", str(64 * 1024))))
    # Comma-separated Host header allow-list (DNS-rebinding defence), e.g. "127.0.0.1,localhost". Empty = any host.
    allowed_hosts: list[str] = field(default_factory=lambda: [h.strip() for h in os.getenv("BASEERA_ALLOWED_HOSTS", "")
                                                              .split(",") if h.strip()])

    @property
    def offline(self) -> bool:
        return self.mode != "live"


def get_settings() -> Settings:
    return Settings()
