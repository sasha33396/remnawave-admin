"""Security helpers for infrastructure resources.

The Remnawave API is trusted to store the complete configuration.  Browser
clients are not: limited administrators only receive redacted documents and
their edits are merged into a freshly fetched trusted copy on the server.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any, Iterable

from fastapi import HTTPException


SECRET_MASK = "********"

_ALWAYS_SECRET_KEYS = {
    "privatekey",
    "secretkey",
    "presharedkey",
    "psk",
}
_CREDENTIAL_KEYS = {"password", "passwd", "auth", "token", "accesstoken"}
_CLIENT_ID_KEYS = {"id", "uuid"}
_IDENTITY_KEYS = ("uuid", "id", "tag", "email", "name", "address")


def _normalise_key(key: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _path_words(path: Iterable[object]) -> set[str]:
    return {_normalise_key(part) for part in path if not isinstance(part, int)}


def is_xray_secret(path: tuple[object, ...], key: object) -> bool:
    """Return whether *key* is confidential at this Xray config location.

    Strong key names are always protected.  Ambiguous names such as ``id`` or
    ``password`` are protected only in authentication-bearing structures, so
    ordinary public/technical values remain visible.
    """
    normal = _normalise_key(key)
    words = _path_words(path)
    if normal in _ALWAYS_SECRET_KEYS:
        return True
    if normal in _CREDENTIAL_KEYS and words & {
        "settings", "servers", "peers", "users", "accounts", "clients",
        "outbounds", "inbounds", "proxysettings", "realitysettings",
    }:
        return True
    if normal in _CLIENT_ID_KEYS and "clients" in words:
        return True
    if normal in {"key", "keyfile"} and words & {
        "certificates", "tlssettings", "realitysettings",
    }:
        return True
    return False


def redact_xray_config(value: Any, path: tuple[object, ...] = ()) -> Any:
    """Deep-copy an Xray document while replacing confidential values."""
    if isinstance(value, dict):
        result: dict[Any, Any] = {}
        for key, child in value.items():
            result[key] = (
                SECRET_MASK
                if is_xray_secret(path, key)
                else redact_xray_config(child, path + (key,))
            )
        return result
    if isinstance(value, list):
        return [redact_xray_config(item, path + (index,)) for index, item in enumerate(value)]
    return copy.deepcopy(value)


def redact_node_secrets(value: Any) -> Any:
    """Remove node/API secrets from arbitrary nested response payloads."""
    if isinstance(value, dict):
        result: dict[Any, Any] = {}
        for key, child in value.items():
            normal = _normalise_key(key)
            if normal in _ALWAYS_SECRET_KEYS or normal in {
                "apitoken", "websecretkey", "jwtsigningsecret", "agenttoken",
            }:
                result[key] = SECRET_MASK
            else:
                result[key] = redact_node_secrets(child)
        return result
    if isinstance(value, list):
        return [redact_node_secrets(item) for item in value]
    return copy.deepcopy(value)


def config_revision(config: Any) -> str:
    """Stable optimistic-concurrency token for a complete trusted config."""
    canonical = json.dumps(config, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _contains_secret(value: Any, path: tuple[object, ...]) -> bool:
    if isinstance(value, dict):
        return any(
            is_xray_secret(path, key) or _contains_secret(child, path + (key,))
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_contains_secret(child, path + (index,)) for index, child in enumerate(value))
    return False


def _public_fingerprint(value: dict[str, Any], path: tuple[object, ...]) -> str:
    public = redact_xray_config(value, path)
    return config_revision(public)


def _identity(value: dict[str, Any], path: tuple[object, ...]) -> tuple[str, str] | None:
    for key in _IDENTITY_KEYS:
        candidate = value.get(key)
        if candidate not in (None, "", SECRET_MASK) and not is_xray_secret(path, key):
            return key, str(candidate)
    # Certificate/key containers often have no UUID/tag.  Match them by their
    # complete public shape, never by array position.
    fingerprint = _public_fingerprint(value, path)
    if fingerprint:
        return "public-shape", fingerprint
    return None


def _merge_list(
    original: list[Any], proposed: list[Any], path: tuple[object, ...], *,
    allow_secret_edit: bool,
    allow_structure_edit: bool,
) -> list[Any]:
    if not any(_contains_secret(item, path + (0,)) for item in original):
        return copy.deepcopy(proposed)
    if not all(isinstance(item, dict) for item in original + proposed):
        raise HTTPException(409, "Protected array cannot be matched safely")

    old_by_identity: dict[tuple[str, str], dict[str, Any]] = {}
    for item in original:
        identity = _identity(item, path)
        if identity is None or identity in old_by_identity:
            raise HTTPException(409, "Protected array has no unique stable identity")
        old_by_identity[identity] = item

    result: list[Any] = []
    seen: set[tuple[str, str]] = set()
    proposed_order: list[tuple[str, str]] = []
    for item in proposed:
        identity = _identity(item, path)
        if identity is None or identity in seen:
            raise HTTPException(409, "Protected array has duplicate or unstable identities")
        seen.add(identity)
        proposed_order.append(identity)
        if identity in old_by_identity:
            result.append(
                merge_protected_config(
                    old_by_identity[identity], item, path=path + (identity[1],),
                    allow_secret_edit=allow_secret_edit,
                    allow_structure_edit=allow_structure_edit,
                )
            )
        elif allow_structure_edit:
            if _contains_secret(item, path) and not allow_secret_edit:
                raise HTTPException(403, "Adding protected objects requires secret edit permission")
            result.append(copy.deepcopy(item))
        else:
            raise HTTPException(409, "Protected array was structurally replaced")
    original_order = list(old_by_identity)
    if not allow_structure_edit and proposed_order != original_order:
        raise HTTPException(409, "Protected array reordering is not allowed")
    removed = set(old_by_identity) - seen
    if removed and (not allow_structure_edit or (
        not allow_secret_edit
        and any(_contains_secret(old_by_identity[key], path) for key in removed)
    )):
        raise HTTPException(403, "Protected object removal is not allowed")
    return result


def merge_protected_config(
    original: Any,
    proposed: Any,
    *,
    path: tuple[object, ...] = (),
    allow_secret_edit: bool = False,
    allow_structure_edit: bool = False,
) -> Any:
    """Merge a redacted client document into a fresh trusted config.

    A limited editor cannot remove, blank, replace or move protected fields.
    Arrays containing secrets are matched by stable object identity/public
    shape; positional matching is deliberately not used.
    """
    if isinstance(original, dict):
        if not isinstance(proposed, dict):
            if _contains_secret(original, path) and not allow_secret_edit:
                raise HTTPException(403, "Protected object replacement is not allowed")
            return copy.deepcopy(proposed)
        result: dict[Any, Any] = {}
        for key, old_value in original.items():
            if is_xray_secret(path, key):
                if key not in proposed:
                    if allow_secret_edit:
                        continue
                    raise HTTPException(403, f"Protected field removed: {key}")
                new_value = proposed[key]
                if allow_secret_edit:
                    if new_value == SECRET_MASK:
                        result[key] = copy.deepcopy(old_value)
                    else:
                        result[key] = copy.deepcopy(new_value)
                else:
                    if new_value not in (SECRET_MASK, old_value):
                        raise HTTPException(403, f"Protected field cannot be changed: {key}")
                    result[key] = copy.deepcopy(old_value)
                continue
            if key in proposed:
                result[key] = merge_protected_config(
                    old_value, proposed[key], path=path + (key,),
                    allow_secret_edit=allow_secret_edit,
                    allow_structure_edit=allow_structure_edit,
                )
            else:
                if _contains_secret(old_value, path + (key,)) and not allow_secret_edit:
                    raise HTTPException(403, f"Protected object removed: {key}")
        for key, new_value in proposed.items():
            if key not in original:
                if is_xray_secret(path, key) and not allow_secret_edit:
                    raise HTTPException(403, f"Protected field cannot be added: {key}")
                result[key] = copy.deepcopy(new_value)
        return result
    if isinstance(original, list):
        if not isinstance(proposed, list):
            if _contains_secret(original, path) and not allow_secret_edit:
                raise HTTPException(403, "Protected array replacement is not allowed")
            return copy.deepcopy(proposed)
        return _merge_list(
            original, proposed, path,
            allow_secret_edit=allow_secret_edit,
            allow_structure_edit=allow_structure_edit,
        )
    return copy.deepcopy(proposed)


def enforce_restricted_xray_policy(original: dict[str, Any], merged: dict[str, Any]) -> None:
    """Permit only infrastructure-safe sections to a limited JSON editor.

    Routing, DNS and outbounds can redirect user traffic or reach internal
    services and therefore require ``config_profiles:full_edit``.
    """
    changed_roots = {
        key for key in set(original) | set(merged)
        if original.get(key) != merged.get(key)
    }
    forbidden = changed_roots - {"log", "inbounds"}
    if forbidden:
        raise HTTPException(
            403,
            "Full Xray edit permission required for: " + ", ".join(sorted(forbidden)),
        )
    old_log = original.get("log") or {}
    new_log = merged.get("log") or {}
    if isinstance(old_log, dict) and isinstance(new_log, dict):
        changed_log = {k for k in set(old_log) | set(new_log) if old_log.get(k) != new_log.get(k)}
        if changed_log - {"loglevel", "dnsLog", "maskAddress"}:
            raise HTTPException(403, "Limited editors may only change safe log settings")


def extract_profile_config(payload: Any) -> dict[str, Any]:
    """Extract ``config`` from known Remnawave 2.8 response envelopes."""
    if not isinstance(payload, dict):
        return {}
    response = payload.get("response", payload)
    if not isinstance(response, dict):
        return {}
    nested = response.get("configProfile")
    config = response.get("config")
    if config is None and isinstance(nested, dict):
        config = nested.get("config")
    return config if isinstance(config, dict) else {}


def redact_profile_payload(payload: Any) -> Any:
    """Redact configs wherever they are nested in a profile API response."""
    if isinstance(payload, dict):
        result: dict[Any, Any] = {}
        for key, value in payload.items():
            if key == "config" and isinstance(value, (dict, list)):
                result[key] = redact_xray_config(value)
            elif key in {"rawInbound", "computedConfig"} and isinstance(value, (dict, list)):
                result[key] = redact_xray_config(value)
            else:
                result[key] = redact_profile_payload(value)
        return result
    if isinstance(payload, list):
        return [redact_profile_payload(item) for item in payload]
    return copy.deepcopy(payload)
