import asyncio
import sys
import os
import logging
import re
import unicodedata
import socket

# Add the project root to the python path
sys.path.append(os.getcwd())
sys.path.append(os.path.join(os.getcwd(), "src"))

from app.infrastructure.database.database import AsyncSessionLocal
from app.infrastructure.database.models import User
from app.infrastructure.auth.manager import UserManager
from app.infrastructure.auth.schemas import UserCreate
from fastapi_users.db import SQLAlchemyUserDatabase

logger = logging.getLogger(__name__)


async def create_superuser():
    async with AsyncSessionLocal() as session:
        user_db = SQLAlchemyUserDatabase(session, User)
        user_manager = UserManager(user_db)

        email = os.environ["BOOTSTRAP_ADMIN_EMAIL"]
        password = os.environ["BOOTSTRAP_ADMIN_PASSWORD"]

        # V02.2.1: Validate email format
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            raise ValueError("BOOTSTRAP_ADMIN_EMAIL must be a valid email address")

        # V06.2.8: Normalize password to NFC Unicode before hashing
        password = unicodedata.normalize("NFC", password)

        # V02.1.1: Enforce minimum password length
        if len(password) < 12:
            raise ValueError("BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters")

        # V02.1.2: Enforce password complexity
        if not (
            re.search(r"[A-Z]", password)
            and re.search(r"[a-z]", password)
            and re.search(r"\d", password)
        ):
            raise ValueError(
                "BOOTSTRAP_ADMIN_PASSWORD must contain upper, lower, and digit characters"
            )

        # V06.2.3 / V06.2.5: Reject common/breached passwords
        COMMON_PASSWORDS = {
            "password",
            "password123",
            "adminpassword",
            "admin",
            "123456",
            "qwerty",
            "changeme",
        }
        if password.lower() in COMMON_PASSWORDS:
            raise ValueError("BOOTSTRAP_ADMIN_PASSWORD is too common")

        # V13.3.2: Require explicit confirmation before creating superuser
        confirm = input(f"Create superuser {email}? [yes/NO] ")
        if confirm.strip().lower() != "yes":
            print("Aborted.")
            sys.exit(0)

        try:
            user = await user_manager.create(
                UserCreate(
                    email=email,
                    password=password,
                    is_superuser=True,
                    is_active=True,
                    is_verified=True,
                )
            )
            logger.info("Superuser created successfully: %s", user.email)
            # V16.3.2 / V16.3.3: Audit-log the critical security event
            logger.warning(
                "AUDIT: superuser created: email=%s host=%s",
                email,
                socket.gethostname(),
            )
        except Exception as e:
            # V16.4.1: Log full exception internally, expose only sanitized message
            logger.error("Superuser creation failed: %s", e)
            raise SystemExit("Superuser creation failed — see logs for details") from e


if __name__ == "__main__":
    asyncio.run(create_superuser())
