# src/app/api/v1/routers/admin_groups.py
"""Admin-only CRUD for user groups + memberships.

Path prefix `/admin/user-groups`. All endpoints are gated on
`current_superuser`; the frontend only shows the Groups page to
admin accounts.
"""

from __future__ import annotations

import logging
import uuid
from typing import List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.auth.core import current_superuser
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.user_group_repo import (
    UserGroupRepository,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/user-groups", tags=["Admin: User Groups"])


# --- Schemas -------------------------------------------------------------


class MemberRead(BaseModel):
    user_id: int
    email: str
    role: str


class UserGroupRead(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str] = None
    created_by: int
    member_count: int
    members: List[MemberRead] = Field(default_factory=list)


class UserGroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None


class UserGroupUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None


class MemberAdd(BaseModel):
    email: EmailStr
    role: str = Field(default="member", pattern="^(member|owner)$")


# --- Helpers -------------------------------------------------------------


def _repo(db: AsyncSession = Depends(get_db)) -> UserGroupRepository:
    return UserGroupRepository(db)


async def _hydrate(
    group: db_models.UserGroup,
    db: AsyncSession,
) -> UserGroupRead:
    # Batch-fetch emails for all members so UI can render them without a
    # per-row round-trip.
    user_ids = [m.user_id for m in (group.memberships or [])]
    email_by_id: dict[int, str] = {}
    if user_ids:
        rows = await db.execute(
            select(db_models.User.id, db_models.User.email).where(
                db_models.User.id.in_(user_ids)
            )
        )
        email_by_id = {uid: email for uid, email in rows.all()}

    members = [
        MemberRead(
            user_id=m.user_id,
            email=email_by_id.get(m.user_id, "(unknown)"),
            role=m.role,
        )
        for m in (group.memberships or [])
    ]
    return UserGroupRead(
        id=group.id,
        name=group.name,
        description=group.description,
        created_by=group.created_by,
        member_count=len(members),
        members=members,
    )


# --- Endpoints -----------------------------------------------------------


@router.get("", response_model=List[UserGroupRead])
async def list_groups(
    _user: db_models.User = Depends(current_superuser),
    repo: UserGroupRepository = Depends(_repo),
    db: AsyncSession = Depends(get_db),
) -> List[UserGroupRead]:
    groups = await repo.list_groups()
    return [await _hydrate(g, db) for g in groups]


@router.post("", response_model=UserGroupRead, status_code=status.HTTP_201_CREATED)
async def create_group(
    payload: UserGroupCreate = Body(...),
    user: db_models.User = Depends(current_superuser),
    repo: UserGroupRepository = Depends(_repo),
    db: AsyncSession = Depends(get_db),
) -> UserGroupRead:
    try:
        group = await repo.create_group(
            name=payload.name,
            description=payload.description,
            created_by=user.id,
        )
    except Exception as e:
        # Most likely: unique violation on `name`.
        logger.warning("Group create failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A group with that name already exists.",
        )
    # Reload with memberships relationship hydrated.
    fresh = await repo.get_group(group.id)
    assert fresh is not None
    return await _hydrate(fresh, db)


@router.patch("/{group_id}", response_model=UserGroupRead)
async def update_group(
    group_id: uuid.UUID,
    payload: UserGroupUpdate = Body(...),
    _user: db_models.User = Depends(current_superuser),
    repo: UserGroupRepository = Depends(_repo),
    db: AsyncSession = Depends(get_db),
) -> UserGroupRead:
    group = await repo.update_group(
        group_id, name=payload.name, description=payload.description
    )
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found.")
    fresh = await repo.get_group(group.id)
    assert fresh is not None
    return await _hydrate(fresh, db)


@router.delete(
    "/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def delete_group(
    group_id: uuid.UUID,
    _user: db_models.User = Depends(current_superuser),
    repo: UserGroupRepository = Depends(_repo),
) -> Response:
    ok = await repo.delete_group(group_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Group not found.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{group_id}/members", response_model=UserGroupRead)
async def add_member(
    group_id: uuid.UUID,
    payload: MemberAdd = Body(...),
    _user: db_models.User = Depends(current_superuser),
    repo: UserGroupRepository = Depends(_repo),
    db: AsyncSession = Depends(get_db),
) -> UserGroupRead:
    group = await repo.get_group(group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found.")

    # Resolve email → user_id. We intentionally don't expose enumeration:
    # if the user doesn't exist we return 404 without distinguishing from
    # "group not found".
    result = await db.execute(
        select(db_models.User).where(db_models.User.email == payload.email)
    )
    user = result.scalars().first()
    if user is None:
        raise HTTPException(
            status_code=404, detail="User with that email does not exist."
        )

    await repo.add_member(group_id, user.id, role=payload.role)
    fresh = await repo.get_group(group_id)
    assert fresh is not None
    return await _hydrate(fresh, db)


@router.delete(
    "/{group_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def remove_member(
    group_id: uuid.UUID,
    user_id: int,
    _user: db_models.User = Depends(current_superuser),
    repo: UserGroupRepository = Depends(_repo),
) -> Response:
    ok = await repo.remove_member(group_id, user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Membership not found.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
