"""Squads management — proxy CRUD to Remnawave Panel API."""
import logging
from typing import Optional, List

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from web.backend.api.deps import require_permission, AdminUser
from web.backend.core.errors import api_error, E
from web.backend.core.rate_limit import limiter, RATE_BULK
from web.backend.core.rbac import get_scope, check_access, resolve_allowed_actions_map
from web.backend.core.resource_security import redact_profile_payload, redact_xray_config

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────

class CreateInternalSquadRequest(BaseModel):
    name: str
    inbounds: List[str] = []


class UpdateInternalSquadRequest(BaseModel):
    name: Optional[str] = None
    inbounds: Optional[List[str]] = None


class CreateExternalSquadRequest(BaseModel):
    name: str


class UpdateExternalSquadRequest(BaseModel):
    name: Optional[str] = None


def _is_unrestricted(admin: AdminUser) -> bool:
    return admin.role == "superadmin" or admin.account_id is None


def _require_action(admin: AdminUser, resource: str, action: str) -> None:
    if not _is_unrestricted(admin) and not admin.has_permission(resource, action):
        raise api_error(403, E.FORBIDDEN)


def _inbound_items(payload: object) -> List[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        items = payload.get("inbounds", [])
        return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []
    return []


def _inbound_uuid(item: dict) -> Optional[str]:
    value = item.get("uuid") or item.get("configProfileInboundUuid")
    return str(value).lower() if value else None


def _profile_uuid(item: dict) -> Optional[str]:
    value = item.get("configProfileUuid") or item.get("profileUuid")
    return str(value).lower() if value else None


async def _load_inbounds() -> List[dict]:
    from shared.api_client import api_client
    try:
        result = await api_client.get_all_inbounds()
        payload = result.get("response", result) if isinstance(result, dict) else result
        return _inbound_items(payload)
    except Exception as exc:
        logger.error("Failed to load squad inbounds: %s", exc)
        raise api_error(502, E.API_SERVICE_UNAVAILABLE)


async def _visible_inbounds(admin: AdminUser) -> tuple[List[dict], Optional[set[str]]]:
    """Return visible inbound metadata and its UUID set for scoped admins."""
    _require_action(admin, "config_profiles", "view")
    items = await _load_inbounds()
    profile_scope = await get_scope(admin, "config_profile", "view")
    if profile_scope is None:
        return items, None
    visible = [item for item in items if _profile_uuid(item) in profile_scope]
    return visible, {uid for item in visible if (uid := _inbound_uuid(item))}


async def _prepare_inbound_update(
    admin: AdminUser, squad_uuid: str, requested: List[str],
) -> List[str]:
    """Validate submitted UUIDs and preserve assignments hidden by profile scope."""
    normalized, visible_ids = await _validate_requested_inbounds(admin, requested)
    if visible_ids is None:
        return requested

    # A scoped admin receives only visible inbounds. Preserve pre-existing
    # assignments outside that scope when the Panel's replace-style API is used.
    from shared.api_client import api_client
    try:
        result = await api_client.get_internal_squads()
        payload = result.get("response", result) if isinstance(result, dict) else result
        squads = payload.get("internalSquads", []) if isinstance(payload, dict) else payload
        squads = squads if isinstance(squads, list) else []
    except Exception as exc:
        logger.error("Failed to load internal squad %s before update: %s", squad_uuid, exc)
        raise api_error(502, E.API_SERVICE_UNAVAILABLE)

    current = next(
        (item for item in squads if str(item.get("uuid", "")).lower() == squad_uuid.lower()),
        None,
    )
    if current is None:
        raise api_error(404, E.NOT_FOUND)
    current_ids = [
        uid for item in (current.get("inbounds") or [])
        if isinstance(item, dict) and (uid := _inbound_uuid(item))
    ]
    hidden_ids = [uid for uid in current_ids if uid not in visible_ids]
    return requested + [uid for uid in hidden_ids if uid not in normalized]


async def _validate_requested_inbounds(
    admin: AdminUser, requested: List[str],
) -> tuple[List[str], Optional[set[str]]]:
    visible, visible_ids = await _visible_inbounds(admin)
    available_ids = {uid for item in visible if (uid := _inbound_uuid(item))}
    normalized = [str(value).lower() for value in requested]
    if len(normalized) != len(set(normalized)) or any(uid not in available_ids for uid in normalized):
        raise api_error(403, E.FORBIDDEN, "One or more inbounds are outside your profile scope")
    return normalized, visible_ids


# ── Internal Squads ──────────────────────────────────────────────

@router.get("/internal")
async def list_internal_squads(
    admin: AdminUser = Depends(require_permission("squads", "view")),
):
    """List internal squads from Panel API."""
    from shared.api_client import api_client
    try:
        result = await api_client.get_internal_squads()
        payload = result.get("response", result) if isinstance(result, dict) else result
        squads = payload.get("internalSquads", []) if isinstance(payload, dict) else payload
        squads = squads if isinstance(squads, list) else []
        scope = await get_scope(admin, "squad", "view")
        if scope is not None:
            squads = [s for s in squads if str(s.get("uuid", "")).lower() in scope]
        actions_map = await resolve_allowed_actions_map(
            admin, "squad", [str(s.get("uuid", "")) for s in squads if s.get("uuid")],
        )
        for s in squads:
            uid = str(s.get("uuid", "")).lower()
            if uid in actions_map:
                s["allowed_actions"] = actions_map[uid]
        return squads
    except Exception as e:
        logger.error("Failed to list internal squads: %s", e)
        raise api_error(502, E.API_SERVICE_UNAVAILABLE)


@router.post("/internal", status_code=201)
@limiter.limit(RATE_BULK)
async def create_internal_squad(
    request: Request,
    body: CreateInternalSquadRequest,
    admin: AdminUser = Depends(require_permission("squads", "create")),
):
    """Create an internal squad via Panel API."""
    inbounds = body.inbounds
    if inbounds:
        _require_action(admin, "squads", "inbounds_edit")
        await _validate_requested_inbounds(admin, inbounds)
    from shared.api_client import api_client
    try:
        result = await api_client.create_internal_squad(body.name, inbounds)
        payload = result.get("response", result) if isinstance(result, dict) else result
        return payload
    except Exception as e:
        logger.error("Failed to create internal squad: %s", e)
        raise api_error(502, E.API_SERVICE_UNAVAILABLE)


@router.patch("/internal/{squad_uuid}")
async def update_internal_squad(
    squad_uuid: str,
    body: UpdateInternalSquadRequest,
    admin: AdminUser = Depends(require_permission("squads", "view")),
):
    """Update an internal squad via Panel API."""
    if body.name is None and body.inbounds is None:
        raise api_error(400, E.NO_FIELDS_TO_UPDATE)
    if body.name is not None:
        _require_action(admin, "squads", "edit")
    if body.inbounds is not None:
        _require_action(admin, "squads", "inbounds_edit")
    if not await check_access(admin, "squad", squad_uuid, "edit"):
        raise api_error(403, E.FORBIDDEN)
    inbounds = (
        await _prepare_inbound_update(admin, squad_uuid, body.inbounds)
        if body.inbounds is not None else None
    )
    from shared.api_client import api_client
    try:
        result = await api_client.update_internal_squad(
            squad_uuid, name=body.name, inbounds=inbounds,
        )
        payload = result.get("response", result) if isinstance(result, dict) else result
        return payload
    except Exception as e:
        logger.error("Failed to update internal squad %s: %s", squad_uuid, e)
        raise api_error(502, E.API_SERVICE_UNAVAILABLE)


@router.delete("/internal/{squad_uuid}")
async def delete_internal_squad(
    squad_uuid: str,
    admin: AdminUser = Depends(require_permission("squads", "delete")),
):
    """Delete an internal squad via Panel API."""
    if not await check_access(admin, "squad", squad_uuid, "delete"):
        raise api_error(403, E.FORBIDDEN)
    from shared.api_client import api_client
    try:
        await api_client.delete_internal_squad(squad_uuid)
        return {"success": True}
    except Exception as e:
        logger.error("Failed to delete internal squad %s: %s", squad_uuid, e)
        raise api_error(502, E.API_SERVICE_UNAVAILABLE)


# ── External Squads ──────────────────────────────────────────────

@router.get("/external")
async def list_external_squads(
    admin: AdminUser = Depends(require_permission("squads", "view")),
):
    """List external squads from Panel API."""
    from shared.api_client import api_client
    try:
        result = await api_client.get_external_squads()
        payload = result.get("response", result) if isinstance(result, dict) else result
        squads = payload.get("externalSquads", []) if isinstance(payload, dict) else payload
        squads = squads if isinstance(squads, list) else []
        scope = await get_scope(admin, "squad", "view")
        if scope is not None:
            squads = [s for s in squads if str(s.get("uuid", "")).lower() in scope]
        actions_map = await resolve_allowed_actions_map(
            admin, "squad", [str(s.get("uuid", "")) for s in squads if s.get("uuid")],
        )
        for s in squads:
            uid = str(s.get("uuid", "")).lower()
            if uid in actions_map:
                s["allowed_actions"] = actions_map[uid]
        return squads
    except Exception as e:
        logger.error("Failed to list external squads: %s", e)
        raise api_error(502, E.API_SERVICE_UNAVAILABLE)


@router.post("/external", status_code=201)
@limiter.limit(RATE_BULK)
async def create_external_squad(
    request: Request,
    body: CreateExternalSquadRequest,
    admin: AdminUser = Depends(require_permission("squads", "create")),
):
    """Create an external squad via Panel API."""
    from shared.api_client import api_client
    try:
        result = await api_client.create_external_squad(body.name)
        payload = result.get("response", result) if isinstance(result, dict) else result
        return payload
    except Exception as e:
        logger.error("Failed to create external squad: %s", e)
        raise api_error(502, E.API_SERVICE_UNAVAILABLE)


@router.patch("/external/{squad_uuid}")
async def update_external_squad(
    squad_uuid: str,
    body: UpdateExternalSquadRequest,
    admin: AdminUser = Depends(require_permission("squads", "edit")),
):
    """Update an external squad via Panel API."""
    if not await check_access(admin, "squad", squad_uuid, "edit"):
        raise api_error(403, E.FORBIDDEN)
    from shared.api_client import api_client
    try:
        payload = {"uuid": squad_uuid}
        if body.name is not None:
            payload["name"] = body.name
        result = await api_client.update_external_squad(payload)
        resp = result.get("response", result) if isinstance(result, dict) else result
        return resp
    except Exception as e:
        logger.error("Failed to update external squad %s: %s", squad_uuid, e)
        raise api_error(502, E.API_SERVICE_UNAVAILABLE)


@router.delete("/external/{squad_uuid}")
async def delete_external_squad(
    squad_uuid: str,
    admin: AdminUser = Depends(require_permission("squads", "delete")),
):
    """Delete an external squad via Panel API."""
    if not await check_access(admin, "squad", squad_uuid, "delete"):
        raise api_error(403, E.FORBIDDEN)
    from shared.api_client import api_client
    try:
        await api_client.delete_external_squad(squad_uuid)
        return {"success": True}
    except Exception as e:
        logger.error("Failed to delete external squad %s: %s", squad_uuid, e)
        raise api_error(502, E.API_SERVICE_UNAVAILABLE)


# ── Inbounds (for squad editing) ─────────────────────────────────

@router.get("/inbounds")
async def list_inbounds(
    admin: AdminUser = Depends(require_permission("squads", "view")),
):
    """List only inbounds from config profiles visible to this admin."""
    items, _ = await _visible_inbounds(admin)
    return redact_xray_config(redact_profile_payload(items))
