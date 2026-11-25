"""Config profiles management — proxy to Remnawave Panel API."""
import json
import logging
from typing import Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from web.backend.api.deps import AdminUser, get_client_ip, require_permission
from web.backend.core.audit import write_audit_log
from web.backend.core.errors import api_error, E
from web.backend.core.rbac import check_access, get_scope
from web.backend.core.resource_security import (
    config_revision,
    enforce_restricted_xray_policy,
    extract_profile_config,
    merge_protected_config,
    redact_profile_payload,
    redact_xray_config,
)

logger = logging.getLogger(__name__)
router = APIRouter()


class ProfileCreate(BaseModel):
    # ограничения панели: 2-30, буквы/цифры/пробел/-/_
    name: str = Field(min_length=2, max_length=30, pattern=r"^[A-Za-z0-9_\s-]+$")
    config: Optional[dict] = None


class ProfileRename(BaseModel):
    name: str = Field(min_length=2, max_length=30, pattern=r"^[A-Za-z0-9_\s-]+$")


#: минимальная заготовка нового профиля. Панель требует >=1 inbound
#: (пустой inbounds -> 500 A112, проверено на 2.8.0) — кладём заглушку
#: на localhost, которую заменяют в редакторе.
_DEFAULT_PROFILE_CONFIG = {
    "log": {"loglevel": "warning"},
    "inbounds": [{
        "tag": "PLACEHOLDER",
        "port": 61000,
        "listen": "127.0.0.1",
        "protocol": "vless",
        "settings": {"clients": [], "decryption": "none"},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
        "streamSettings": {"network": "raw", "security": "none"},
    }],
    "outbounds": [
        {"tag": "DIRECT", "protocol": "freedom"},
        {"tag": "BLOCK", "protocol": "blackhole"},
    ],
}


def _can_view_secrets(admin: AdminUser) -> bool:
    return (
        admin.role == "superadmin"
        or admin.account_id is None
        or admin.has_permission("config_profiles", "secrets_view")
    )


async def _require_profile_access(admin: AdminUser, profile_uuid: str, action: str) -> None:
    if not await check_access(admin, "config_profile", profile_uuid, action):
        # Hide the existence of profiles outside the policy scope.
        raise api_error(404, E.NOT_FOUND)


async def _deny_scoped_create(admin: AdminUser, resource_type: str) -> None:
    """A whitelist cannot safely auto-include a newly created resource."""
    if await get_scope(admin, resource_type, "view") is not None:
        raise api_error(403, E.FORBIDDEN, "Creation is disabled by the attached access policy")


def _profile_uuid_from_node(node: dict) -> Optional[str]:
    profile = node.get("configProfile") or node.get("config_profile") or {}
    if isinstance(profile, dict):
        return profile.get("activeConfigProfileUuid") or profile.get("active_config_profile_uuid")
    return node.get("configProfileUuid") or node.get("config_profile_uuid")


async def _assert_profile_nodes_editable(admin: AdminUser, profile_uuid: str) -> None:
    """Reject edits to a shared profile when any affected node is out of scope."""
    if admin.role == "superadmin" or admin.account_id is None:
        return
    from shared.api_client import api_client

    result = await api_client.get_nodes(skip_cache=True)
    payload = result.get("response", result) if isinstance(result, dict) else {}
    nodes = payload.get("nodes", []) if isinstance(payload, dict) else []
    affected = [
        str(node.get("uuid")) for node in nodes
        if isinstance(node, dict) and _profile_uuid_from_node(node) == profile_uuid and node.get("uuid")
    ]
    if not affected:
        return
    if not admin.has_permission("nodes", "edit"):
        raise api_error(403, E.FORBIDDEN, "Profile is assigned to nodes you cannot edit")
    for node_uuid in affected:
        if not await check_access(admin, "node", node_uuid, "edit"):
            raise api_error(403, E.FORBIDDEN, "Profile is shared with a node outside your access policy")


def _profile_response(payload: object, admin: AdminUser) -> object:
    return payload if _can_view_secrets(admin) else redact_profile_payload(payload)


@router.get("")
async def list_config_profiles(
    admin: AdminUser = Depends(require_permission("config_profiles", "view")),
):
    """List all config profiles."""
    try:
        from shared.api_client import api_client
        result = await api_client.get_config_profiles()
        payload = result.get("response", {})
        profiles = payload.get("configProfiles", []) if isinstance(payload, dict) else []
        scope = await get_scope(admin, "config_profile", "view")
        if scope is not None:
            profiles = [p for p in profiles if str(p.get("uuid", "")).lower() in scope]
        profiles = _profile_response(profiles, admin)
        return {"items": profiles, "total": len(profiles)}
    except Exception as e:
        logger.error("Failed to list config profiles (%s)", type(e).__name__)
        raise HTTPException(status_code=502, detail="Service temporarily unavailable")


@router.post("")
async def create_config_profile(
    data: ProfileCreate,
    request: Request,
    admin: AdminUser = Depends(require_permission("config_profiles", "create")),
):
    """Создать профиль (пустая заготовка, дальше — встроенный редактор)."""
    from shared.api_client import api_client
    from shared.exceptions import ServerError, ValidationError
    await _deny_scoped_create(admin, "config_profile")
    if (
        data.config is not None
        and admin.role != "superadmin"
        and admin.account_id is not None
        and not admin.has_permission("config_profiles", "full_edit")
    ):
        raise api_error(403, E.FORBIDDEN, "Custom initial JSON requires full Xray edit permission")
    try:
        result = await api_client.create_config_profile({
            "name": data.name,
            "config": data.config or _DEFAULT_PROFILE_CONFIG,
        })
    except (ValidationError, ServerError) as e:
        logger.warning("Panel rejected config profile creation (%s)", type(e).__name__)
        raise HTTPException(status_code=400, detail="Panel rejected the configuration")
    except Exception as e:
        logger.error("Failed to create config profile (%s)", type(e).__name__)
        raise HTTPException(status_code=502, detail="Service temporarily unavailable")

    try:
        await write_audit_log(
            admin_id=admin.account_id, admin_username=admin.username,
            action="config_profile.create", resource="resources",
            resource_id=data.name, ip_address=get_client_ip(request),
        )
    except Exception as e:
        logger.warning("Audit log for config_profile.create failed: %s", e)
    return _profile_response(result.get("response", result), admin)


@router.get("/tools/x25519")
async def generate_x25519(
    admin: AdminUser = Depends(require_permission("config_profiles", "secrets_edit")),
):
    """Пары ключей x25519 для Reality (генерит панель)."""
    try:
        from shared.api_client import api_client
        result = await api_client.generate_x25519()
        return result.get("response", result)
    except Exception as e:
        logger.error("Failed to generate x25519 (%s)", type(e).__name__)
        raise HTTPException(status_code=502, detail="Service temporarily unavailable")


@router.get("/inbounds")
async def list_inbounds(
    admin: AdminUser = Depends(require_permission("config_profiles", "view")),
):
    """List all inbounds."""
    try:
        from shared.api_client import api_client
        result = await api_client.get_all_inbounds()
        payload = result.get("response", result)
        scope = await get_scope(admin, "config_profile", "view")
        if scope is not None:
            items = payload if isinstance(payload, list) else payload.get("inbounds", []) if isinstance(payload, dict) else []
            filtered = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                profile_uuid = item.get("configProfileUuid") or item.get("profileUuid")
                if profile_uuid and str(profile_uuid).lower() in scope:
                    filtered.append(item)
            payload = filtered
        return _profile_response(payload, admin)
    except Exception as e:
        logger.error("Failed to list inbounds (%s)", type(e).__name__)
        raise HTTPException(status_code=502, detail="Service temporarily unavailable")


@router.get("/{profile_uuid}/inbounds")
async def list_profile_inbounds(
    profile_uuid: str,
    admin: AdminUser = Depends(require_permission("config_profiles", "view")),
):
    """List inbounds for a specific config profile."""
    await _require_profile_access(admin, profile_uuid, "view")
    try:
        from shared.api_client import api_client
        result = await api_client.get_inbounds_by_profile_uuid(profile_uuid)
        return _profile_response(result.get("response", result), admin)
    except Exception as e:
        logger.error("Failed to list profile inbounds (%s)", type(e).__name__)
        raise HTTPException(status_code=502, detail="Service temporarily unavailable")


@router.get("/{profile_uuid}")
async def get_config_profile(
    profile_uuid: str,
    admin: AdminUser = Depends(require_permission("config_profiles", "view")),
):
    """Get a single config profile."""
    await _require_profile_access(admin, profile_uuid, "view")
    try:
        from shared.api_client import api_client
        result = await api_client.get_config_profile_by_uuid(profile_uuid)
        payload = result.get("response", result)
        config = extract_profile_config(payload)
        response = _profile_response(payload, admin)
        if isinstance(response, dict):
            response = dict(response)
            response["_revision"] = config_revision(config)
        return response
    except Exception as e:
        logger.error("Failed to get config profile (%s)", type(e).__name__)
        raise HTTPException(status_code=502, detail="Service temporarily unavailable")


@router.get("/{profile_uuid}/computed-config")
async def get_computed_config(
    profile_uuid: str,
    admin: AdminUser = Depends(require_permission("config_profiles", "view")),
):
    """Get the computed (expanded) config for a profile."""
    await _require_profile_access(admin, profile_uuid, "view")
    try:
        from shared.api_client import api_client
        result = await api_client.get_config_profile_computed(profile_uuid)
        return _profile_response(result.get("response", result), admin)
    except Exception as e:
        logger.error("Failed to get computed config (%s)", type(e).__name__)
        raise HTTPException(status_code=502, detail="Service temporarily unavailable")


@router.get("/{profile_uuid}/versions")
async def list_profile_versions(
    profile_uuid: str,
    admin: AdminUser = Depends(require_permission("config_profiles", "view")),
):
    """История сохранений профиля через встроенный редактор (метаданные)."""
    await _require_profile_access(admin, profile_uuid, "view")
    from shared.database import db_service
    return {"items": await db_service.list_config_versions("profile", profile_uuid)}


@router.get("/versions/{version_id}")
async def get_profile_version(
    version_id: int,
    admin: AdminUser = Depends(require_permission("config_profiles", "view")),
):
    """Содержимое конкретной версии (для отката/диффа в редакторе)."""
    from shared.database import db_service
    version = await db_service.get_config_version(version_id)
    if not version or version.get("entity_type") != "profile":
        raise HTTPException(status_code=404, detail="Version not found")
    await _require_profile_access(admin, str(version.get("entity_id", "")), "view")
    if not _can_view_secrets(admin) and version.get("content"):
        try:
            version = dict(version)
            version["content"] = json.dumps(
                redact_xray_config(json.loads(version["content"])),
                ensure_ascii=False,
                indent=2,
            )
        except (TypeError, ValueError):
            raise HTTPException(status_code=500, detail="Stored profile version is invalid")
    return version


async def _snapshot_profile_baseline(profile_uuid: str) -> None:
    """Перед первым нашим сохранением зафиксировать исходный конфиг панели."""
    from shared.database import db_service
    from shared.api_client import api_client
    existing = await db_service.list_config_versions("profile", profile_uuid, limit=1)
    if existing:
        return
    result = await api_client.get_config_profile_by_uuid(profile_uuid)
    payload = result.get("response", result) or {}
    cfg = payload.get("config") or (payload.get("configProfile") or {}).get("config")
    if cfg:
        await db_service.save_config_version(
            "profile", profile_uuid, json.dumps(cfg, ensure_ascii=False, indent=2),
            entity_name=payload.get("name") or (payload.get("configProfile") or {}).get("name"),
            created_by="baseline",
        )


@router.patch("/{profile_uuid}")
async def update_config_profile(
    profile_uuid: str,
    request: Request,
    config: dict = Body(...),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    admin: AdminUser = Depends(require_permission("config_profiles", "edit")),
):
    """Patch a config profile's xray-config JSON (used by xray-editor page)."""
    await _require_profile_access(admin, profile_uuid, "edit")
    await _assert_profile_nodes_editable(admin, profile_uuid)
    try:
        from shared.api_client import api_client
        from shared.exceptions import NotFoundError, ServerError, ValidationError
        trusted_result = await api_client.get_config_profile_by_uuid(profile_uuid)
        trusted_payload = trusted_result.get("response", trusted_result)
        original = extract_profile_config(trusted_payload)
        if not original:
            raise HTTPException(status_code=409, detail="Trusted profile configuration is unavailable")
        current_revision = config_revision(original)
        if not if_match:
            raise HTTPException(status_code=428, detail="If-Match revision is required")
        if if_match and if_match.strip('"') != current_revision:
            raise HTTPException(status_code=409, detail="Profile changed since it was loaded; reload and retry")

        is_superadmin = admin.role == "superadmin" or admin.account_id is None
        allow_secret_edit = is_superadmin or admin.has_permission("config_profiles", "secrets_edit")
        allow_structure_edit = is_superadmin or admin.has_permission("config_profiles", "full_edit")
        merged = merge_protected_config(
            original,
            config,
            allow_secret_edit=allow_secret_edit,
            allow_structure_edit=allow_structure_edit,
        )
        if not allow_structure_edit:
            enforce_restricted_xray_policy(original, merged)

        # Baseline is the exact trusted document used for the merge.
        from shared.database import db_service
        existing_versions = await db_service.list_config_versions("profile", profile_uuid, limit=1)
        if not existing_versions:
            await db_service.save_config_version(
                "profile", profile_uuid,
                json.dumps(original, ensure_ascii=False, indent=2),
                entity_name=trusted_payload.get("name") if isinstance(trusted_payload, dict) else None,
                created_by="baseline",
            )
        # Panel expects the JSON payload `{ uuid, config }` to PATCH /api/config-profiles.
        result = await api_client.update_config_profile({"uuid": profile_uuid, "config": merged})
    except HTTPException:
        raise
    except (ValidationError, ServerError) as e:
        # бизнес-ошибка панели (напр. «All inbounds must have a unique tag») —
        # редактор должен показать её текст, а не generic 502
        logger.warning("Panel rejected config for %s (%s)", profile_uuid, type(e).__name__)
        raise HTTPException(status_code=400, detail="Panel rejected the configuration")
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Config profile not found")
    except Exception as e:
        logger.error("Failed to update config profile %s (%s)", profile_uuid, type(e).__name__)
        raise HTTPException(status_code=502, detail="Service temporarily unavailable")

    # снапшот новой версии (дедуп по хэшу внутри)
    try:
        from shared.database import db_service
        await db_service.save_config_version(
            "profile", profile_uuid,
            json.dumps(merged, ensure_ascii=False, indent=2),
            created_by=admin.username,
        )
    except Exception as e:
        logger.warning("Version snapshot for %s failed: %s", profile_uuid, e)

    try:
        await write_audit_log(
            admin_id=admin.account_id,
            admin_username=admin.username,
            action="config_profile.update",
            resource="resources",
            resource_id=profile_uuid,
            details=json.dumps({"keys": sorted(list(merged.keys()))[:20]}) if isinstance(merged, dict) else None,
            ip_address=get_client_ip(request),
        )
    except Exception as e:
        logger.warning("Audit log for config_profile.update failed: %s", e)

    payload = result.get("response", result)
    return _profile_response(payload, admin)


@router.patch("/{profile_uuid}/name")
async def rename_config_profile(
    profile_uuid: str,
    data: ProfileRename,
    request: Request,
    admin: AdminUser = Depends(require_permission("config_profiles", "edit")),
):
    """Переименовать профиль (контракт панели: PATCH {uuid, name})."""
    await _require_profile_access(admin, profile_uuid, "edit")
    await _assert_profile_nodes_editable(admin, profile_uuid)
    from shared.api_client import api_client
    from shared.exceptions import NotFoundError, ServerError, ValidationError
    try:
        result = await api_client.update_config_profile({"uuid": profile_uuid, "name": data.name})
    except (ValidationError, ServerError) as e:
        logger.warning("Panel rejected profile rename for %s (%s)", profile_uuid, type(e).__name__)
        raise HTTPException(status_code=400, detail="Panel rejected the profile name")
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Config profile not found")
    except Exception as e:
        logger.error("Failed to rename config profile %s (%s)", profile_uuid, type(e).__name__)
        raise HTTPException(status_code=502, detail="Service temporarily unavailable")

    try:
        await write_audit_log(
            admin_id=admin.account_id, admin_username=admin.username,
            action="config_profile.rename", resource="resources",
            resource_id=profile_uuid, details=json.dumps({"name": data.name}),
            ip_address=get_client_ip(request),
        )
    except Exception as e:
        logger.warning("Audit log for config_profile.rename failed: %s", e)
    return _profile_response(result.get("response", result), admin)


@router.delete("/{profile_uuid}")
async def delete_config_profile(
    profile_uuid: str,
    request: Request,
    admin: AdminUser = Depends(require_permission("config_profiles", "delete")),
):
    """Удалить профиль из панели (история версий у нас остаётся)."""
    await _require_profile_access(admin, profile_uuid, "delete")
    await _assert_profile_nodes_editable(admin, profile_uuid)
    from shared.api_client import api_client
    from shared.exceptions import NotFoundError, ServerError, ValidationError
    try:
        result = await api_client.delete_config_profile(profile_uuid)
    except (ValidationError, ServerError) as e:
        # напр. профиль привязан к нодам — панель откажет, доносим причину
        logger.warning("Panel rejected profile deletion for %s (%s)", profile_uuid, type(e).__name__)
        raise HTTPException(status_code=400, detail="Panel rejected profile deletion")
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Config profile not found")
    except Exception as e:
        logger.error("Failed to delete config profile %s (%s)", profile_uuid, type(e).__name__)
        raise HTTPException(status_code=502, detail="Service temporarily unavailable")

    try:
        await write_audit_log(
            admin_id=admin.account_id, admin_username=admin.username,
            action="config_profile.delete", resource="resources",
            resource_id=profile_uuid, ip_address=get_client_ip(request),
        )
    except Exception as e:
        logger.warning("Audit log for config_profile.delete failed: %s", e)
    return result.get("response", result)
