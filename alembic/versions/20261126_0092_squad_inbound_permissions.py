"""Separate squad RBAC and allow safe inbound assignment.

Revision ID: 0092
Revises: 0091
Create Date: 2026-11-26

Existing user-management roles retain the squad privileges they had before
the resource was split. Infrastructure Admin receives only squad visibility
and the ability to change internal-squad inbound assignments.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0092"
down_revision: Union[str, None] = "0091"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _grant(conn, role_name: str, resource: str, actions: list[str]) -> None:
    role_id = conn.execute(
        sa.text("SELECT id FROM admin_roles WHERE name = :name"), {"name": role_name},
    ).scalar()
    if not role_id:
        return
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

    # Squads historically reused users CRUD permissions. Preserve that access
    # while making the two domains independently assignable going forward.
    conn.execute(sa.text("""
        INSERT INTO admin_permissions (role_id, resource, action)
        SELECT role_id, 'squads', action
        FROM admin_permissions
        WHERE resource = 'users' AND action IN ('view', 'create', 'edit', 'delete')
        ON CONFLICT DO NOTHING
    """))
    conn.execute(sa.text("""
        INSERT INTO admin_permissions (role_id, resource, action)
        SELECT role_id, 'squads', 'inbounds_edit'
        FROM admin_permissions
        WHERE resource = 'users' AND action = 'edit'
        ON CONFLICT DO NOTHING
    """))

    _grant(
        conn, "superadmin", "squads",
        ["view", "create", "edit", "delete", "inbounds_edit"],
    )
    _grant(conn, "infrastructure_admin", "squads", ["view", "inbounds_edit"])


def downgrade() -> None:
    op.execute("DELETE FROM admin_permissions WHERE resource = 'squads'")
