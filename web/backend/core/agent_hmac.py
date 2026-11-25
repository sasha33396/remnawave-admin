"""HMAC-SHA256 signing and verification for agent commands.

Every command sent from backend to agent is signed with HMAC-SHA256.
Key material: a per-agent secret derived from NODE_AGENT_HMAC_SECRET.
Payload includes a timestamp for replay protection (60s window).
"""
import hashlib
import hmac
import json
import time
from typing import Any, Dict

from web.backend.core.config import get_web_settings


def get_agent_install_secret(agent_token: str) -> str:
    """Derive a secret scoped to one agent without exposing the server root.

    The returned value may be placed in an install command: compromising it
    does not reveal the JWT signing key or another node's HMAC key.
    """
    settings = get_web_settings()
    root = settings.node_agent_hmac_secret
    if not root:
        raise RuntimeError(
            "NODE_AGENT_HMAC_SECRET must be configured before generating new agent install commands"
        )
    if not agent_token.startswith("v2."):
        raise RuntimeError("Rotate the legacy agent token before generating an install command")
    return hmac.new(root.encode(), agent_token.encode(), hashlib.sha256).hexdigest()


def _derive_key(agent_token: str) -> bytes:
    """Derive the same final key that the installed agent calculates.

    An unset dedicated root deliberately retains the pre-3.1.1 key derivation
    for already installed agents.  New install commands are disabled in that
    mode so WEB_SECRET_KEY is never disclosed to another machine.
    """
    settings = get_web_settings()
    if settings.node_agent_hmac_secret and agent_token.startswith("v2."):
        install_secret = get_agent_install_secret(agent_token)
    else:
        install_secret = settings.secret_key
    return hashlib.sha256(
        f"{install_secret}:{agent_token}".encode()
    ).digest()


def sign_command(payload: Dict[str, Any], agent_token: str) -> str:
    """Sign a command payload with HMAC-SHA256.

    Adds a `_ts` timestamp field to the payload before signing.
    Returns the hex-encoded signature.
    """
    payload_copy = dict(payload)
    payload_copy["_ts"] = int(time.time())

    canonical = json.dumps(payload_copy, sort_keys=True, separators=(",", ":"))
    key = _derive_key(agent_token)
    sig = hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()
    return sig


def sign_command_with_ts(payload: Dict[str, Any], agent_token: str) -> tuple[Dict[str, Any], str]:
    """Sign a command payload and return (payload_with_ts, signature)."""
    payload_copy = dict(payload)
    payload_copy["_ts"] = int(time.time())

    canonical = json.dumps(payload_copy, sort_keys=True, separators=(",", ":"))
    key = _derive_key(agent_token)
    sig = hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()
    return payload_copy, sig


def verify_command_signature(
    payload: Dict[str, Any],
    signature: str,
    agent_token: str,
    max_age_seconds: int = 60,
) -> bool:
    """Verify HMAC signature and check timestamp freshness.

    Returns True if signature is valid and timestamp is within max_age_seconds.
    """
    ts = payload.get("_ts")
    if ts is None:
        return False

    # Check replay window
    now = int(time.time())
    if abs(now - ts) > max_age_seconds:
        return False

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    key = _derive_key(agent_token)
    expected = hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
