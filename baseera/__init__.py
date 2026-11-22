"""Baseera (بصيرة): fraudulent link & fake listing detector for UAE residents."""
import logging

__version__ = "0.1.0"

# httpx logs full request URLs at INFO, and some APIs (GSB, SerpAPI) take the key as a query parameter.
# Keep httpx at WARNING so a verbose logging config can never print a key (CLAUDE.md rule 5).
logging.getLogger("httpx").setLevel(logging.WARNING)
