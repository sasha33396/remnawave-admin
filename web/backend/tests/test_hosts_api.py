"""Tests for hosts API — /api/v2/hosts/*."""
import pytest
from unittest.mock import patch, AsyncMock

from fastapi import HTTPException

from web.backend.api.deps import get_current_admin, get_api_client
from .conftest import make_admin


MOCK_HOST_API = {
    "uuid": "host-111",
    "remark": "my-host",
    "address": "example.com",
    "port": 443,
    "isDisabled": False,
    "viewPosition": 0,
    "inbound": {"configProfileInboundUuid": "inbound-1"},
    "sni": "example.com",
    "host": "example.com",
    "path": "/ws",
    "security": "tls",
    "securityLayer": "tls",
    "alpn": "h2,http/1.1",
    "fingerprint": "chrome",
    "tag": None,
    "serverDescription": None,
    "isHidden": False,
    "shuffleHost": False,
    "mihomoX25519": False,
    "nodes": [],
    "excludedInternalSquads": [],
    "createdAt": "2026-01-01T00:00:00Z",
    "updatedAt": "2026-02-01T00:00:00Z",
}


class TestMapHost:
    """Tests for _map_host and _map_host_detail helpers."""

    def test_map_host_basic(self):
        from web.backend.api.v2.hosts import _map_host
        result = _map_host(MOCK_HOST_API)
        assert result["uuid"] == "host-111"
        assert result["remark"] == "my-host"
        assert result["is_disabled"] is False
        assert result["inbound_uuid"] == "inbound-1"
        assert result["sni"] == "example.com"

    def test_map_host_detail(self):
        from web.backend.api.v2.hosts import _map_host_detail
        result = _map_host_detail(MOCK_HOST_API)
        assert result["created_at"] == "2026-01-01T00:00:00Z"
        assert result["verify_peer_cert_by_name"] is False
        assert result["pinned_peer_cert_sha256"] is None

    def test_null_bools_coerced_to_false(self):
        """Remnawave 2.8.0 присылает null в булевых полях (напр. verifyPeerCertByName
        без пиннинга) — валидация не должна падать, None приводится к False."""
        from web.backend.schemas.host import HostListItem, HostDetail
        raw = {
            "uuid": "h-null", "remark": "r", "address": "a", "port": 443,
            "is_disabled": None, "is_hidden": None, "shuffle_host": None,
            "mihomo_x25519": None, "verify_peer_cert_by_name": None,
        }
        item = HostListItem(**raw)
        assert item.verify_peer_cert_by_name is False
        assert item.is_disabled is False
        assert item.is_hidden is False
        assert item.shuffle_host is False
        assert item.mihomo_x25519 is False
        detail = HostDetail(**raw, override_sni_from_address=None, keep_sni_blank=None)
        assert detail.override_sni_from_address is False
        assert detail.keep_sni_blank is False


class TestListHosts:
    """GET /api/v2/hosts."""

    @pytest.mark.asyncio
    @patch(
        "web.backend.api.v2.hosts._get_hosts_list",
        new_callable=AsyncMock,
        return_value=[MOCK_HOST_API, MOCK_HOST_API],
    )
    async def test_list_hosts_success(self, mock_get, client):
        resp = await client.get("/api/v2/hosts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2

    @pytest.mark.asyncio
    @patch(
        "web.backend.api.v2.hosts._get_hosts_list",
        new_callable=AsyncMock,
        return_value=[],
    )
    async def test_list_hosts_empty(self, mock_get, client):
        resp = await client.get("/api/v2/hosts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_list_hosts_as_viewer_allowed(self, app, viewer):
        """Viewers have hosts.view permission."""
        app.dependency_overrides[get_current_admin] = lambda: viewer
        from httpx import ASGITransport, AsyncClient
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            with patch("web.backend.api.v2.hosts._get_hosts_list", new_callable=AsyncMock, return_value=[]):
                resp = await ac.get("/api/v2/hosts")
                assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_list_hosts_anon_unauthorized(self, anon_client):
        resp = await anon_client.get("/api/v2/hosts")
        assert resp.status_code == 401


class TestListHostsRBAC:
    """RBAC tests for host write operations."""

    @pytest.mark.asyncio
    async def test_viewer_cannot_create_host(self, app, viewer):
        """Viewers don't have hosts.create permission."""
        app.dependency_overrides[get_current_admin] = lambda: viewer
        from httpx import ASGITransport, AsyncClient
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post("/api/v2/hosts", json={"remark": "test"})
            assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_operator_cannot_create_host(self, app, operator):
        """Operators don't have hosts.create permission."""
        app.dependency_overrides[get_current_admin] = lambda: operator
        from httpx import ASGITransport, AsyncClient
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post("/api/v2/hosts", json={"remark": "test"})
            assert resp.status_code == 403


class TestHostInboundAssignment:
    """Profile/inbound assignment is available without granting secret access."""

    @pytest.mark.asyncio
    async def test_update_can_remove_inbound_assignment(self, app, client):
        api = AsyncMock()
        api.update_host_raw.return_value = {"response": MOCK_HOST_API}
        app.dependency_overrides[get_api_client] = lambda: api

        with patch("web.backend.api.v2.hosts.check_access", new=AsyncMock(return_value=True)), \
             patch("web.backend.api.v2.hosts.write_audit_log", new=AsyncMock()):
            resp = await client.patch("/api/v2/hosts/host-111", json={"inbound": None})

        assert resp.status_code == 200
        api.update_host_raw.assert_awaited_once()
        assert api.update_host_raw.await_args.args[0]["inbound"] is None

    @pytest.mark.asyncio
    async def test_infrastructure_admin_can_assign_visible_profile(self):
        from web.backend.api.v2.hosts import _require_inbound_assignment_access

        admin = make_admin(
            "infrastructure_admin",
            permissions={("hosts", "edit"), ("config_profiles", "view")},
        )
        inbound = {
            "configProfileUuid": "profile-1",
            "configProfileInboundUuid": "inbound-1",
        }
        access = AsyncMock(return_value=True)
        with patch("web.backend.api.v2.hosts.check_access", new=access):
            await _require_inbound_assignment_access(admin, inbound)

        access.assert_awaited_once_with(admin, "config_profile", "profile-1", "view")

    @pytest.mark.asyncio
    async def test_assignment_requires_profile_view_permission(self):
        from web.backend.api.v2.hosts import _require_inbound_assignment_access

        admin = make_admin(
            "limited",
            permissions={("hosts", "edit")},
        )
        inbound = {
            "configProfileUuid": "profile-1",
            "configProfileInboundUuid": "inbound-1",
        }
        with pytest.raises(HTTPException) as exc:
            await _require_inbound_assignment_access(admin, inbound)

        assert exc.value.status_code == 403
