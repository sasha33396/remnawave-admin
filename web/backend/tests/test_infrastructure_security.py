"""Regression tests for infrastructure RBAC and secret-preserving edits."""
import hashlib
import hmac
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from web.backend.api.deps import get_current_admin
from web.backend.core.audit import sanitize_audit_details
from web.backend.core.resource_security import (
    SECRET_MASK,
    config_revision,
    enforce_restricted_xray_policy,
    merge_protected_config,
    redact_node_secrets,
    redact_xray_config,
)
from .conftest import make_admin


@pytest.fixture()
def xray_config():
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "VLESS",
            "protocol": "vless",
            "settings": {"clients": [{"id": "client-secret", "email": "one@example.test"}]},
            "streamSettings": {"realitySettings": {"privateKey": "reality-secret"}},
        }],
        "outbounds": [{"tag": "DIRECT", "protocol": "freedom"}],
    }


def test_recursive_redaction_masks_xray_and_node_secrets(xray_config):
    redacted = redact_xray_config(xray_config)
    assert redacted["inbounds"][0]["settings"]["clients"][0]["id"] == SECRET_MASK
    assert redacted["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"] == SECRET_MASK
    node = redact_node_secrets({"uuid": "n1", "SecretKey": "node-secret", "nested": {"agentToken": "tok"}})
    assert node == {"uuid": "n1", "SecretKey": SECRET_MASK, "nested": {"agentToken": SECRET_MASK}}


def test_safe_merge_preserves_masked_values_and_allows_safe_log_edit(xray_config):
    proposed = redact_xray_config(xray_config)
    proposed["log"]["loglevel"] = "info"
    merged = merge_protected_config(xray_config, proposed)
    assert merged["inbounds"][0]["settings"]["clients"][0]["id"] == "client-secret"
    assert merged["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"] == "reality-secret"
    enforce_restricted_xray_policy(xray_config, merged)


@pytest.mark.parametrize("mutation", ["change", "remove", "null"])
def test_safe_merge_rejects_secret_change_removal_or_null(xray_config, mutation):
    proposed = redact_xray_config(xray_config)
    reality = proposed["inbounds"][0]["streamSettings"]["realitySettings"]
    if mutation == "change":
        reality["privateKey"] = "attacker-value"
    elif mutation == "remove":
        del reality["privateKey"]
    else:
        reality["privateKey"] = None
    with pytest.raises(HTTPException) as exc:
        merge_protected_config(xray_config, proposed)
    assert exc.value.status_code in {403, 409}


def test_safe_merge_rejects_protected_reorder_duplicate_and_tag_rename(xray_config):
    second = {
        "tag": "SECOND",
        "settings": {"clients": [{"id": "second-secret", "email": "two@example.test"}]},
    }
    original = dict(xray_config)
    original["inbounds"] = [xray_config["inbounds"][0], second]

    reordered = redact_xray_config(original)
    reordered["inbounds"].reverse()
    with pytest.raises(HTTPException):
        merge_protected_config(original, reordered)

    duplicated = redact_xray_config(original)
    duplicated["inbounds"][1]["tag"] = "VLESS"
    with pytest.raises(HTTPException):
        merge_protected_config(original, duplicated)

    renamed = redact_xray_config(original)
    renamed["inbounds"][0]["tag"] = "RENAMED"
    with pytest.raises(HTTPException):
        merge_protected_config(original, renamed)


def test_full_and_secret_permissions_allow_structural_secret_edit(xray_config):
    proposed = redact_xray_config(xray_config)
    proposed["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"] = "rotated"
    proposed["inbounds"].append({"tag": "NEW", "settings": {"clients": [{"id": "new-secret"}]}})
    merged = merge_protected_config(
        xray_config,
        proposed,
        allow_secret_edit=True,
        allow_structure_edit=True,
    )
    assert merged["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"] == "rotated"
    assert len(merged["inbounds"]) == 2


def test_restricted_policy_blocks_routing_and_outbound_changes(xray_config):
    changed = dict(xray_config)
    changed["routing"] = {"rules": []}
    with pytest.raises(HTTPException) as exc:
        enforce_restricted_xray_policy(xray_config, changed)
    assert exc.value.status_code == 403


def test_audit_sanitizer_never_serializes_secret_values():
    clean = sanitize_audit_details(
        '{"privateKey":"reality-secret","nested":{"token":"agent-token"},"name":"safe"}'
    )
    assert "reality-secret" not in clean
    assert "agent-token" not in clean
    assert '"name": "safe"' in clean


def test_agent_hmac_legacy_compatibility_and_secure_install_derivation():
    from web.backend.core import agent_hmac

    token = "node-token"
    legacy = SimpleNamespace(secret_key="jwt-root", node_agent_hmac_secret=None)
    with patch.object(agent_hmac, "get_web_settings", return_value=legacy):
        expected = hashlib.sha256(b"jwt-root:node-token").digest()
        assert agent_hmac._derive_key(token) == expected
        with pytest.raises(RuntimeError):
            agent_hmac.get_agent_install_secret(token)

    secure_token = "v2.node-token"
    secure = SimpleNamespace(secret_key="jwt-root", node_agent_hmac_secret="agent-root")
    with patch.object(agent_hmac, "get_web_settings", return_value=secure):
        install_secret = agent_hmac.get_agent_install_secret(secure_token)
        assert install_secret == hmac.new(
            b"agent-root", secure_token.encode(), hashlib.sha256,
        ).hexdigest()
        assert "jwt-root" not in install_secret
        assert agent_hmac._derive_key(secure_token) == hashlib.sha256(
            f"{install_secret}:{secure_token}".encode()
        ).digest()


@pytest.mark.asyncio
async def test_limited_profile_read_masks_and_patch_preserves_secret(client, app, xray_config):
    admin = make_admin(
        role="infrastructure_admin",
        account_id=44,
        permissions={("config_profiles", "view"), ("config_profiles", "edit"), ("nodes", "edit")},
    )
    app.dependency_overrides[get_current_admin] = lambda: admin
    api = AsyncMock()
    api.get_nodes = AsyncMock(return_value={"response": {"nodes": []}})
    api.get_config_profile_by_uuid = AsyncMock(
        return_value={"response": {"uuid": "profile-1", "name": "Main", "config": xray_config}}
    )
    api.update_config_profile = AsyncMock(
        return_value={"response": {"uuid": "profile-1", "config": xray_config}}
    )
    db = AsyncMock()
    db.is_connected = False
    db.list_config_versions = AsyncMock(return_value=[{"id": 1}])
    proposed = redact_xray_config(xray_config)
    proposed["log"]["loglevel"] = "info"

    with patch("shared.api_client.api_client", api), \
         patch("shared.database.db_service", db), \
         patch("web.backend.api.v2.config_profiles.check_access", new=AsyncMock(return_value=True)):
        read = await client.get("/api/v2/config-profiles/profile-1")
        assert read.status_code == 200
        assert read.json()["config"]["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"] == SECRET_MASK

        saved = await client.patch(
            "/api/v2/config-profiles/profile-1",
            json=proposed,
            headers={"If-Match": config_revision(xray_config)},
        )
        assert saved.status_code == 200

    sent = api.update_config_profile.await_args.args[0]["config"]
    assert sent["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"] == "reality-secret"
    assert sent["log"]["loglevel"] == "info"


@pytest.mark.asyncio
async def test_profile_patch_rejects_stale_revision_before_panel_write(client, app, xray_config):
    admin = make_admin(
        role="infrastructure_admin",
        account_id=45,
        permissions={("config_profiles", "edit"), ("nodes", "edit")},
    )
    app.dependency_overrides[get_current_admin] = lambda: admin
    api = AsyncMock()
    api.get_nodes = AsyncMock(return_value={"response": {"nodes": []}})
    api.get_config_profile_by_uuid = AsyncMock(
        return_value={"response": {"uuid": "profile-1", "config": xray_config}}
    )
    with patch("shared.api_client.api_client", api), \
         patch("web.backend.api.v2.config_profiles.check_access", new=AsyncMock(return_value=True)):
        response = await client.patch(
            "/api/v2/config-profiles/profile-1",
            json=redact_xray_config(xray_config),
            headers={"If-Match": "stale"},
        )
    assert response.status_code == 409
    api.update_config_profile.assert_not_awaited()
