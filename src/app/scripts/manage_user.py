# src/app/scripts/manage_user.py
import asyncio
import argparse
import sys
import logging
import getpass
import re
import socket
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
    logger.info("Attempting to manage user: %s", email)

    # --- START: Self-contained database connection ---
    if not settings.ASYNC_DATABASE_URL:
        raise ValueError("ASYNC_DATABASE_URL not set!")

    engine = create_async_engine(settings.ASYNC_DATABASE_URL)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    # --- END: Self-contained database connection ---

    async with session_factory() as session:
        db_adapter_generator = get_user_db(session)
        # anext is a builtin in Python 3.10+
        db = await anext(db_adapter_generator)  # noqa: F821
        user_manager_generator = get_user_manager(db)
        user_manager = await anext(user_manager_generator)  # noqa: F821

        user_to_update = await user_manager.get_by_email(email)

        if not user_to_update:
            logger.error("User with email %s not found.", email)
            return

        user_to_update = cast(User, user_to_update)
        update_dict: Dict[str, Any] = {}

        if superuser is not None and user_to_update.is_superuser != superuser:
            update_dict["is_superuser"] = superuser
            logger.info("Updating is_superuser to: %s", superuser)

        if verified is not None and user_to_update.is_verified != verified:
            update_dict["is_verified"] = verified
            logger.info("Updating is_verified to: %s", verified)

        # V02.2.3: auto-set is_verified when granting superuser
        if update_dict.get("is_superuser"):
            update_dict["is_verified"] = True

        # V13.3.2 / V02.3.2: confirmation prompt for elevated flag grants
        if update_dict.get("is_superuser") or update_dict.get("is_verified"):
            confirm = input(
                f"Grant elevated flags {list(update_dict)} to {user_to_update.email}? [yes/NO] "
            )
            if confirm.strip().lower() != "yes":
                logger.info("Aborted by operator.")
                print("Aborted.")
                return

        if update_dict:
            # V16.3.2 / V16.3.3 / V02.3.2: audit log before superuser elevation
            if update_dict.get("is_superuser"):
                logger.warning(
                    "AUDIT: superuser grant: user=%s actor=%s host=%s",
                    user_to_update.email,
                    getpass.getuser(),
                    socket.gethostname(),
                )

            # Corrected: Create a UserUpdate schema instance from the dictionary
            user_update_schema = UserUpdate(**update_dict)
            # Corrected: Pass the schema to the user_manager's update method
            # V02.3.3: wrap update in try/except for transactional safety
            try:
                await user_manager.update(user_update_schema, user_to_update)
            except Exception as e:
                logger.error("Failed to update user %s: %s", user_to_update.email, e)
                raise
            logger.info("Successfully updated user: %s", email)
        else:
            logger.info("No changes were needed for the user.")


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

    # V02.2.1: validate email format before proceeding
    EMAIL_RE = re.compile(r"^[^@]+@[^@]+\.[^@]+$")
    if not EMAIL_RE.match(args.email):
        print("Invalid email format")
        sys.exit(1)

    if args.superuser is None and args.verified is None:
        logger.error(
            "You must specify at least one action (--superuser or --verified)."
        )
        sys.exit(1)

    await manage_user(
        email=args.email, superuser=args.superuser, verified=args.verified
    )


if __name__ == "__main__":
    asyncio.run(main())
