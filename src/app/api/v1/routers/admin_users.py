import logging
import secrets
import string
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr

from app.infrastructure.auth.core import current_superuser
from app.infrastructure.auth.manager import UserManager, get_user_manager
from app.infrastructure.database.models import User
from app.infrastructure.auth.schemas import UserRead

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["Admin: Users"])

class AdminUserCreate(BaseModel):
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
    # Check if user already exists
    try:
        existing_user = await user_manager.get_by_email(user_in.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists."
            )
    except Exception:
        pass # get_by_email might raise if not found

    # Generate a strong, random placeholder password
    alphabet = string.ascii_letters + string.digits + string.punctuation
    placeholder_password = ''.join(secrets.choice(alphabet) for i in range(32))

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
        created_user = await user_manager.create(create_schema, safe=True)
        
        # Trigger the forgot password flow to send the setup email
        await user_manager.forgot_password(created_user)
        
        logger.info(f"Admin created a new user {created_user.email} and trigger an email setup.")
        return created_user

    except Exception as e:
        logger.error(f"Failed to create user {user_in.email} via admin: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the user."
        )

@router.get(
    "/users",
    response_model=List[UserRead],
    dependencies=[Depends(current_superuser)],
)
async def admin_list_users(
    user_manager: UserManager = Depends(get_user_manager),
):
    """
    Lists all users.
    Accessible only to superusers.
    """
    users = []
    # FastAPI users generic db doesn't have a list method by default but the underlying db does
    # Let's bypass to sql alchemy or try to fetch all if the user_db exposes it.
    # We can get the session from the user_manager.user_db.session
    try:
        from sqlalchemy import select
        result = await user_manager.user_db.session.execute(select(User))
        users = result.scalars().all()
    except Exception as e:
        logger.error(f"Error fetching users list: {e}")
        raise HTTPException(status_code=500, detail="Could not retrieve users")
    return users
