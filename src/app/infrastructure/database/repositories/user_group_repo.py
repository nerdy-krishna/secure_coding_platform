# src/app/infrastructure/database/repositories/user_group_repo.py
"""Repository for the `user_groups` + `user_group_memberships` tables.

The hot path here is `get_peer_user_ids(user_id)` — called on every
request that needs to compute scan visibility (Dashboard, Projects,
Compliance, Search). Kept as a single query against the memberships
table joined to itself.
"""

from __future__ import annotations

import logging
import uuid
from typing import List, Optional, Set

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)


class UserGroupRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    # --- Group CRUD (admin surface) ------------------------------------

    async def create_group(
        self,
        *,
        name: str,
        description: Optional[str],
        created_by: int,
    ) -> db_models.UserGroup:
        group = db_models.UserGroup(
            name=name, description=description, created_by=created_by
        )
        self.db.add(group)
        await self.db.commit()
        await self.db.refresh(group)
        return group

    async def update_group(
        self,
        group_id: uuid.UUID,
        *,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Optional[db_models.UserGroup]:
        group = await self.db.get(db_models.UserGroup, group_id)
        if group is None:
            return None
        if name is not None:
            group.name = name
        if description is not None:
            group.description = description
        await self.db.commit()
        await self.db.refresh(group)
        return group

    async def delete_group(self, group_id: uuid.UUID) -> bool:
        group = await self.db.get(db_models.UserGroup, group_id)
        if group is None:
            return False
        await self.db.delete(group)
        await self.db.commit()
        return True

    async def list_groups(self) -> List[db_models.UserGroup]:
        stmt = (
            select(db_models.UserGroup)
            .options(selectinload(db_models.UserGroup.memberships))
            .order_by(db_models.UserGroup.name)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_group(self, group_id: uuid.UUID) -> Optional[db_models.UserGroup]:
        stmt = (
            select(db_models.UserGroup)
            .options(selectinload(db_models.UserGroup.memberships))
            .where(db_models.UserGroup.id == group_id)
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def count_members(self, group_id: uuid.UUID) -> int:
        stmt = (
            select(func.count())
            .select_from(db_models.UserGroupMembership)
            .where(db_models.UserGroupMembership.group_id == group_id)
        )
        return int(await self.db.scalar(stmt) or 0)

    # --- Membership ----------------------------------------------------

    async def add_member(
        self, group_id: uuid.UUID, user_id: int, *, role: str = "member"
    ) -> db_models.UserGroupMembership:
        # Idempotent: return the existing row when already a member.
        existing = await self.db.get(
            db_models.UserGroupMembership, {"group_id": group_id, "user_id": user_id}
        )
        if existing:
            if existing.role != role:
                existing.role = role
                await self.db.commit()
                await self.db.refresh(existing)
            return existing
        membership = db_models.UserGroupMembership(
            group_id=group_id, user_id=user_id, role=role
        )
        self.db.add(membership)
        await self.db.commit()
        await self.db.refresh(membership)
        return membership

    async def remove_member(self, group_id: uuid.UUID, user_id: int) -> bool:
        existing = await self.db.get(
            db_models.UserGroupMembership, {"group_id": group_id, "user_id": user_id}
        )
        if existing is None:
            return False
        await self.db.delete(existing)
        await self.db.commit()
        return True

    # --- Hot path for scan visibility ---------------------------------

    async def get_peer_user_ids(self, user_id: int) -> Set[int]:
        """Return the set of user_ids that share at least one group with
        `user_id`. Result excludes `user_id` itself; callers should add
        it back when they want the full visibility list.

        Implementation: a single SELECT DISTINCT from memberships joined
        to itself by group_id. Hot path, so keeping it a single roundtrip.
        """
        m1 = db_models.UserGroupMembership.__table__.alias("m1")
        m2 = db_models.UserGroupMembership.__table__.alias("m2")
        stmt = (
            select(m2.c.user_id)
            .distinct()
            .select_from(m1.join(m2, m1.c.group_id == m2.c.group_id))
            .where(m1.c.user_id == user_id)
            .where(m2.c.user_id != user_id)
        )
        result = await self.db.execute(stmt)
        return {row[0] for row in result.all()}

    async def list_groups_for_user(self, user_id: int) -> List[db_models.UserGroup]:
        stmt = (
            select(db_models.UserGroup)
            .join(
                db_models.UserGroupMembership,
                db_models.UserGroupMembership.group_id == db_models.UserGroup.id,
            )
            .where(db_models.UserGroupMembership.user_id == user_id)
            .order_by(db_models.UserGroup.name)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    # --- Utilities used by admin flow ---------------------------------

    async def delete_memberships_for_user(self, user_id: int) -> int:
        """Remove `user_id` from every group. Returns the count deleted.
        Used when an admin deactivates or deletes a user."""
        stmt = delete(db_models.UserGroupMembership).where(
            db_models.UserGroupMembership.user_id == user_id
        )
        result = await self.db.execute(stmt)
        await self.db.commit()
        return result.rowcount or 0
