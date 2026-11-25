"""Infrastructure RBAC permissions and profile access-policy scopes.

Revision ID: 0091
Revises: 0090
Create Date: 2026-11-25

Existing limited roles deliberately receive no new permissions.  This avoids
turning the former broad ``resources`` grant into access to newly separated
secret-bearing resources.  The superadmin role is extended explicitly and a
safe Infrastructure Admin system role is seeded.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0091"
down_revision: Union[str, None] = "0090"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


SUPERADMIN_PERMISSIONS = {
    "nodes": [
        "restart", "enable", "disable", "secrets_view", "secrets_edit",
    ],
    "config_profiles": [
        "view", "create", "edit", "delete", "secrets_view", "secrets_edit",
        "full_edit",
    ],
    "subscription_templates": ["view", "create", "edit", "delete"],
    "snippets": ["view", "create", "edit", "delete"],
    "node_agents": ["view", "manage", "tokens_manage", "install"],
}

INFRASTRUCTURE_PERMISSIONS = {
    "nodes": ["view", "create", "edit", "restart", "enable", "disable"],
    "hosts": ["view", "create", "edit"],
    "config_profiles": ["view", "create", "edit"],
}


def _grant(conn, role_name: str, permissions: dict[str, list[str]]) -> None:
    role_id = conn.execute(
        sa.text("SELECT id FROM admin_roles WHERE name = :name"), {"name": role_name},
    ).scalar()
    if not role_id:
        return
    for resource, actions in permissions.items():
        for action in actions:
            conn.execute(
                sa.text(
                    "INSERT INTO admin_permissions (role_id, resource, action) "
                    "VALUES (:role_id, :resource, :action) ON CONFLICT DO NOTHING"
                ),
                {"role_id": role_id, "resource": resource, "action": action},
            )


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(sa.text("""
        INSERT INTO admin_roles (name, display_name, description, is_system)
        VALUES (
            'infrastructure_admin', 'Infrastructure Admin',
            'Infrastructure management without users, destructive actions, or secrets', true
        )
        ON CONFLICT (name) DO NOTHING
    """))
    _grant(conn, "superadmin", SUPERADMIN_PERMISSIONS)
    _grant(conn, "infrastructure_admin", INFRASTRUCTURE_PERMISSIONS)

    # Preserve the non-secret meaning of the former broad `resources`
    # permission.  No secret/full-edit/node-agent right is inferred.
    conn.execute(sa.text("""
        INSERT INTO admin_permissions (role_id, resource, action)
        SELECT DISTINCT p.role_id, target.resource, p.action
        FROM admin_permissions p
        CROSS JOIN (VALUES
            ('config_profiles'), ('subscription_templates'), ('snippets')
        ) AS target(resource)
        WHERE p.resource = 'resources'
          AND p.action IN ('view', 'create', 'edit', 'delete')
        ON CONFLICT DO NOTHING
    """))
    # Node lifecycle operations were historically covered by nodes:edit.
    conn.execute(sa.text("""
        INSERT INTO admin_permissions (role_id, resource, action)
        SELECT DISTINCT p.role_id, 'nodes', lifecycle.action
        FROM admin_permissions p
        CROSS JOIN (VALUES ('restart'), ('enable'), ('disable')) AS lifecycle(action)
        WHERE p.resource = 'nodes' AND p.action = 'edit'
        ON CONFLICT DO NOTHING
    """))

    # Access policies can now scope configuration profiles and express an
    # explicit all-resources rule.  Recreate CHECK constraints in-place.
    op.execute("ALTER TABLE access_policy_rules DROP CONSTRAINT IF EXISTS ck_apr_resource_type")
    op.execute("""
        ALTER TABLE access_policy_rules ADD CONSTRAINT ck_apr_resource_type
        CHECK (resource_type IN ('node','host','squad','user','config_profile'))
    """)
    op.execute("ALTER TABLE access_policy_rules DROP CONSTRAINT IF EXISTS ck_apr_scope_type")
    op.execute("""
        ALTER TABLE access_policy_rules ADD CONSTRAINT ck_apr_scope_type
        CHECK (scope_type IN ('uuid','tag','all'))
    """)


def downgrade() -> None:
    conn = op.get_bind()
    role_id = conn.execute(
        sa.text("SELECT id FROM admin_roles WHERE name = 'infrastructure_admin'")
    ).scalar()
    if role_id:
        conn.execute(sa.text("DELETE FROM admin_permissions WHERE role_id = :id"), {"id": role_id})
        conn.execute(sa.text("DELETE FROM admin_roles WHERE id = :id"), {"id": role_id})

    conn.execute(sa.text("""
        DELETE FROM admin_permissions
        WHERE resource IN ('config_profiles', 'subscription_templates', 'snippets', 'node_agents')
           OR (resource = 'nodes' AND action IN (
               'restart', 'enable', 'disable', 'secrets_view', 'secrets_edit'
           ))
    """))

    op.execute(
        "DELETE FROM access_policy_rules "
        "WHERE resource_type IN ('config_profile', 'user') OR scope_type = 'all'"
    )
    op.execute("ALTER TABLE access_policy_rules DROP CONSTRAINT IF EXISTS ck_apr_resource_type")
    op.execute("""
        ALTER TABLE access_policy_rules ADD CONSTRAINT ck_apr_resource_type
        CHECK (resource_type IN ('node','host','squad'))
    """)
    op.execute("ALTER TABLE access_policy_rules DROP CONSTRAINT IF EXISTS ck_apr_scope_type")
    op.execute("""
        ALTER TABLE access_policy_rules ADD CONSTRAINT ck_apr_scope_type
        CHECK (scope_type IN ('uuid','tag'))
    """)
