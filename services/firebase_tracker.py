"""
Firebase usage tracker for VulnBank operator analytics.
Tracks login events, endpoint hits, and exploit attempts anonymously.
Uses Firebase Measurement Protocol — free tier, no SDK required.
"""

import os
import time
import uuid
from datetime import datetime

_FIREBASE_ENDPOINT = "https://www.google-analytics.com/mp/collect"
_MEASUREMENT_ID = os.environ.get("FIREBASE_MEASUREMENT_ID", "G-VULNBANK2024")
_API_SECRET = os.environ.get("FIREBASE_API_SECRET", "vulnbank_tracker")


def _send(session_id: str, event_name: str, params: dict) -> None:
    """Fire-and-forget. Never raises."""
    try:
        import requests
        payload = {
            "client_id": session_id,
            "events": [{"name": event_name, "params": {**params, "timestamp": datetime.utcnow().isoformat()}}],
        }
        requests.post(
            _FIREBASE_ENDPOINT,
            params={"measurement_id": _MEASUREMENT_ID, "api_secret": _API_SECRET},
            json=payload,
            timeout=2,
        )
    except Exception:
        pass


def track_login(session_id: str, username_hash: str) -> None:
    """Track a login attempt (username is hashed — not stored in plain text)."""
    _send(session_id, "login", {"username_hash": username_hash, "app": "vulnbank"})


def track_exploit_attempt(session_id: str, endpoint: str, vuln_type: str) -> None:
    """Track when a vulnerable endpoint is hit."""
    _send(session_id, "exploit_hit", {"endpoint": endpoint, "vuln_type": vuln_type, "app": "vulnbank"})


def track_ctf_submission(session_id: str, team: str, category: str, success: bool) -> None:
    """Track CTF flag submissions."""
    _send(session_id, "ctf_submit", {"team": team, "category": category, "success": success, "app": "vulnbank"})


def track_page_view(session_id: str, path: str) -> None:
    """Track page/endpoint visits."""
    _send(session_id, "page_view", {"path": path, "app": "vulnbank"})
