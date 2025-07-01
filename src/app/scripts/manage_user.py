# src/app/scripts/manage_user.py
import asyncio
import argparse
import sys
import logging
from typing import cast, Dict, Any

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

# Corrected: Import central settings, User model, and the UserUpdate schema
from app.config.config import settings
from app.infrastructure.database.models import User
from app.infrastructure.auth.schemas import UserUpdate

# Import the user manager and its dependencies
from app.infrastructure.auth.manager import get_user_manager
from app.infrastructure.auth.db import get_user_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def manage_user(email: str, superuser: bool, verified: bool):
    """
    Finds a user by email and updates their superuser and verified status.
    """
    print(f"Attempting to manage user: {email}")

    # --- START: Self-contained database connection ---
    if not settings.ASYNC_DATABASE_URL:
        raise ValueError("ASYNC_DATABASE_URL not set!")

    engine = create_async_engine(settings.ASYNC_DATABASE_URL)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    # --- END: Self-contained database connection ---

    async with session_factory() as session:
        db_adapter_generator = get_user_db(session)
        db = await anext(db_adapter_generator)
        user_manager_generator = get_user_manager(db)
        user_manager = await anext(user_manager_generator)

        user_to_update = await user_manager.get_by_email(email)

        if not user_to_update:
            print(f"Error: User with email {email} not found.")
            return

        user_to_update = cast(User, user_to_update)
        update_dict: Dict[str, Any] = {}

        if superuser is not None and user_to_update.is_superuser != superuser:
            update_dict["is_superuser"] = superuser
            print(f"Updating is_superuser to: {superuser}")

        if verified is not None and user_to_update.is_verified != verified:
            update_dict["is_verified"] = verified
            print(f"Updating is_verified to: {verified}")

        if update_dict:
            # Corrected: Create a UserUpdate schema instance from the dictionary
            user_update_schema = UserUpdate(**update_dict)
            # Corrected: Pass the schema to the user_manager's update method
            await user_manager.update(user_update_schema, user_to_update)
            print(f"Successfully updated user: {email}")
        else:
            print("No changes were needed for the user.")


async def main():
    parser = argparse.ArgumentParser(description="Manage user properties.")
    parser.add_argument(
        "--email", type=str, required=True, help="Email of the user to manage."
    )
    parser.add_argument(
        "--superuser",
        action=argparse.BooleanOptionalAction,
        help="Set or unset superuser status.",
    )
    parser.add_argument(
        "--verified",
        action=argparse.BooleanOptionalAction,
        help="Set or unset verified status.",
    )
    args = parser.parse_args()

    if args.superuser is None and args.verified is None:
        print(
            "Error: You must specify at least one action (--superuser or --verified)."
        )
        sys.exit(1)

    await manage_user(
        email=args.email, superuser=args.superuser, verified=args.verified
    )


if __name__ == "__main__":
    asyncio.run(main())
