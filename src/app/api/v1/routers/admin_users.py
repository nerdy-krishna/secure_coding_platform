import logging
import secrets
import string
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, EmailStr
from sqlalchemy.exc import IntegrityError

from app.infrastructure.auth.core import current_superuser
from app.infrastructure.auth.manager import UserManager, get_user_manager
from app.infrastructure.database.models import User
from app.infrastructure.auth.schemas import UserRead

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["Admin: Users"])


class AdminUserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    is_active: bool = True
    is_superuser: bool = False
    is_verified: bool = False


@router.post(
    "/users",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(current_superuser)],
)
async def admin_create_user(
    user_in: AdminUserCreate,
    user_manager: UserManager = Depends(get_user_manager),
):
    """
    Creates a new user and sends them a password setup email.
    Accessible only to superusers.
    """
    logger.info("admin.users.create_attempt")
    # Check if user already exists
    try:
        existing_user = await user_manager.get_by_email(user_in.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists.",
            )
    except Exception:
        pass  # get_by_email might raise if not found

    # Generate a strong, random placeholder password
    alphabet = string.ascii_letters + string.digits + string.punctuation
    placeholder_password = "".join(secrets.choice(alphabet) for i in range(32))

    try:
        # We need a proper user dict for fastapi_users user_manager.create
        from app.infrastructure.auth.schemas import UserCreate

        create_schema = UserCreate(
            email=user_in.email,
            password=placeholder_password,
            is_active=user_in.is_active,
            is_superuser=user_in.is_superuser,
            is_verified=user_in.is_verified,
        )
        try:
            created_user = await user_manager.create(create_schema, safe=True)
        except IntegrityError:
            # TOCTOU backstop: concurrent request with same email hit the DB unique constraint
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists.",
            )

        # Trigger the forgot password flow to send the setup email
        await user_manager.forgot_password(created_user)

        logger.info(
            "admin.users.created",
            extra={
                "user_id": str(created_user.id),
                "is_superuser": user_in.is_superuser,
                "is_active": user_in.is_active,
            },
        )
        return created_user

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(
            "admin.users.create_failed",
            extra={"error_type": type(e).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the user.",
        )


@router.get(
    "/users",
    response_model=List[UserRead],
    dependencies=[Depends(current_superuser)],
)
async def admin_list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    user_manager: UserManager = Depends(get_user_manager),
):
    """
    Lists all users with pagination.
    Accessible only to superusers.
    Results are paginated via skip/limit parameters (default: skip=0, limit=100, max limit=1000).
    """
    users = []
    # NOTE: fastapi-users' generic user_db has no list helper, so we bypass to raw SQLAlchemy
    # here. This is the ONLY place in this module where that bypass is intentional and allowed.
    # The session is obtained from user_manager.user_db.session as provided by the dependency.
    try:
        from sqlalchemy import select

        result = await user_manager.user_db.session.execute(
            select(User).order_by(User.id).offset(skip).limit(limit)
        )
        users = result.scalars().all()
        logger.info("admin.users.listed", extra={"result_count": len(users)})
    except Exception:
        logger.exception("admin.users.list_failed")
        raise HTTPException(status_code=500, detail="Could not retrieve users")
    return users
