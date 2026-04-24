# src/app/shared/lib/scan_scope.py
"""Helpers for computing which users' data a caller is allowed to see.

A regular user sees scans owned by themselves **plus** scans owned by
anyone in a group they also belong to. Admins see everything.

Consumers use the return value as a SQL filter argument:

    visible = await visible_user_ids(user, repo)
    if visible is not None:
        stmt = stmt.where(Project.user_id.in_(visible))

The sentinel (`None`) means "no filter" — the admin path — not "no
access."
"""

from __future__ import annotations

from typing import List, Optional

from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.user_group_repo import (
    UserGroupRepository,
)


async def visible_user_ids(
    user: db_models.User,
    repo: UserGroupRepository,
) -> Optional[List[int]]:
    """Return the list of user_ids visible to `user`, or None for admins.

    Regular users always include their own id plus peers from all
    groups they belong to. Admins get `None` so callers skip the
    filter entirely.
    """
    if user.is_superuser:
        return None
    peers = await repo.get_peer_user_ids(user.id)
    return [user.id, *sorted(peers)]
