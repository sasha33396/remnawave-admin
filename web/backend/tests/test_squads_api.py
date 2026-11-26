"""RBAC and profile-scope regression tests for squads."""
from unittest.mock import AsyncMock, patch

import pytest

from web.backend.api.deps import get_current_admin
from web.backend.core.resource_security import SECRET_MASK
from .conftest import make_admin


def _infrastructure_admin():
    return make_admin(
        role="infrastructure_admin",
        account_id=92,
        permissions={
            ("squads", "view"),
            ("squads", "inbounds_edit"),
            ("config_profiles", "view"),
        },
    )


@pytest.mark.asyncio
async def test_infrastructure_admin_can_change_internal_squad_inbounds(client, app):
    admin = _infrastructure_admin()
    app.dependency_overrides[get_current_admin] = lambda: admin
    api = AsyncMock()
    api.get_all_inbounds.return_value = {
        "response": [{
            "uuid": "inbound-1",
            "tag": "VLESS",
            "type": "vless",
            "configProfileUuid": "profile-1",
        }]
    }
    api.update_internal_squad.return_value = {
        "response": {"uuid": "squad-1", "inbounds": [{"uuid": "inbound-1"}]}
    }

    with patch("shared.api_client.api_client", api), \
         patch("web.backend.api.v2.squads.get_scope", new=AsyncMock(return_value=None)), \
         patch("web.backend.api.v2.squads.check_access", new=AsyncMock(return_value=True)):
        response = await client.patch(
            "/api/v2/squads/internal/squad-1", json={"inbounds": ["inbound-1"]},
        )

    assert response.status_code == 200
    api.update_internal_squad.assert_awaited_once_with(
        "squad-1", name=None, inbounds=["inbound-1"],
    )


@pytest.mark.asyncio
async def test_infrastructure_admin_cannot_rename_internal_squad(client, app):
    admin = _infrastructure_admin()
    app.dependency_overrides[get_current_admin] = lambda: admin
    api = AsyncMock()

    with patch("shared.api_client.api_client", api):
        response = await client.patch(
            "/api/v2/squads/internal/squad-1", json={"name": "Renamed"},
        )

    assert response.status_code == 403
    api.update_internal_squad.assert_not_awaited()


@pytest.mark.asyncio
async def test_inbound_list_is_profile_scoped_and_redacted(client, app):
    admin = _infrastructure_admin()
    app.dependency_overrides[get_current_admin] = lambda: admin
    api = AsyncMock()
    api.get_all_inbounds.return_value = {"response": [
        {
            "uuid": "visible-inbound",
            "tag": "VISIBLE",
            "configProfileUuid": "visible-profile",
            "privateKey": "top-level-secret",
            "rawInbound": {
                "settings": {"clients": [{"id": "client-secret"}]},
                "streamSettings": {"realitySettings": {"privateKey": "private-secret"}},
            },
        },
        {
            "uuid": "hidden-inbound",
            "tag": "HIDDEN",
            "configProfileUuid": "hidden-profile",
        },
    ]}

    with patch("shared.api_client.api_client", api), \
         patch(
             "web.backend.api.v2.squads.get_scope",
             new=AsyncMock(return_value={"visible-profile"}),
         ):
        response = await client.get("/api/v2/squads/inbounds")

    assert response.status_code == 200
    assert [item["uuid"] for item in response.json()] == ["visible-inbound"]
    raw = response.json()[0]["rawInbound"]
    assert response.json()[0]["privateKey"] == SECRET_MASK
    assert raw["settings"]["clients"][0]["id"] == SECRET_MASK
    assert raw["streamSettings"]["realitySettings"]["privateKey"] == SECRET_MASK


@pytest.mark.asyncio
async def test_scoped_update_preserves_hidden_existing_inbounds(client, app):
    admin = _infrastructure_admin()
    app.dependency_overrides[get_current_admin] = lambda: admin
    api = AsyncMock()
    api.get_all_inbounds.return_value = {"response": [
        {
            "uuid": "visible-inbound",
            "configProfileUuid": "visible-profile",
        },
        {
            "uuid": "hidden-inbound",
            "configProfileUuid": "hidden-profile",
        },
    ]}
    api.get_internal_squads.return_value = {"response": {"internalSquads": [{
        "uuid": "squad-1",
        "inbounds": [{"uuid": "visible-inbound"}, {"uuid": "hidden-inbound"}],
    }]}}
    api.update_internal_squad.return_value = {"response": {"uuid": "squad-1"}}

    with patch("shared.api_client.api_client", api), \
         patch(
             "web.backend.api.v2.squads.get_scope",
             new=AsyncMock(return_value={"visible-profile"}),
         ), \
         patch("web.backend.api.v2.squads.check_access", new=AsyncMock(return_value=True)):
        response = await client.patch(
            "/api/v2/squads/internal/squad-1", json={"inbounds": []},
        )

    assert response.status_code == 200
    api.update_internal_squad.assert_awaited_once_with(
        "squad-1", name=None, inbounds=["hidden-inbound"],
    )


@pytest.mark.asyncio
async def test_scoped_update_rejects_inbound_uuid_injection(client, app):
    admin = _infrastructure_admin()
    app.dependency_overrides[get_current_admin] = lambda: admin
    api = AsyncMock()
    api.get_all_inbounds.return_value = {"response": [{
        "uuid": "hidden-inbound",
        "configProfileUuid": "hidden-profile",
    }]}

    with patch("shared.api_client.api_client", api), \
         patch(
             "web.backend.api.v2.squads.get_scope",
             new=AsyncMock(return_value={"visible-profile"}),
         ), \
         patch("web.backend.api.v2.squads.check_access", new=AsyncMock(return_value=True)):
        response = await client.patch(
            "/api/v2/squads/internal/squad-1", json={"inbounds": ["hidden-inbound"]},
        )

    assert response.status_code == 403
    api.update_internal_squad.assert_not_awaited()
