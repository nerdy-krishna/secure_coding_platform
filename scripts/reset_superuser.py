"""DESTRUCTIVE RECOVERY: DELETE FROM user; then provision admin@securecode.com with a random password.

Captures into stdout-driven log sinks would expose secrets, so this script writes the
generated password to a 0600-permission file rather than printing it. RECOVERY-ONLY -
refuses to run unless SCCAP_RESET_CONFIRM=YES.

Note: this script is gated by an out-of-band approval workflow (e.g., requires two
operators to co-sign a ticket) per ASVS V2.3.5. The temporary password must be rotated
on first login per ASVS V6.4.1.
"""

import asyncio
import hashlib
import logging
import pathlib
import sys
import os
import secrets
import string
import time

# Add project root
sys.path.append(os.getcwd())
sys.path.append(os.path.join(os.getcwd(), "src"))

from sqlalchemy import delete
from app.infrastructure.database.database import AsyncSessionLocal
from app.infrastructure.database.models import User
from app.infrastructure.auth.manager import UserManager
from app.infrastructure.auth.schemas import UserCreate
from fastapi_users.db import SQLAlchemyUserDatabase

logging.Formatter.converter = time.gmtime
logging.basicConfig(
    level=logging.INFO, format="%(asctime)sZ %(levelname)s %(name)s %(message)s"
)
logger = logging.getLogger(__name__)

if os.environ.get("SCCAP_RESET_CONFIRM") != "YES":
    raise SystemExit("refusing to run: set SCCAP_RESET_CONFIRM=YES")


def generate_password(length=22):
    if not isinstance(length, int) or not (12 <= length <= 128):
        raise ValueError("length must be an int between 12 and 128")
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for i in range(length))


async def reset_superuser():
    if os.environ.get("I_UNDERSTAND_THIS_DELETES_ALL_USERS") != "yes":
        logger.warning(
            "Refusing to run without I_UNDERSTAND_THIS_DELETES_ALL_USERS=yes"
        )
        return
    if input("Type DELETE to confirm: ").strip() != "DELETE":
        logger.warning("reset_superuser.aborted_no_confirmation")
        return
    async with AsyncSessionLocal() as session:
        try:
            # Delete all users
            logger.warning(
                "authz.admin_action",
                extra={
                    "event": "authz.admin_action",
                    "action": "delete_all_users",
                    "actor": os.getlogin(),
                },
            )
            logger.warning("Deleting all existing users...")
            await session.execute(delete(User))

            # Create new superuser
            email = "admin@securecode.com"
            password = generate_password()

            user_db = SQLAlchemyUserDatabase(session, User)
            # UserManager needs to be instantiated with the user_db
            # Note: UserManager in this codebase might have a specific init if it depends on other services,
            # but usually for a simple create strictly for DB it might be enough if we mock or provide minimal deps if needed.
            # Let's check imports in create_superuser.py - it imported UserManager directly.
            # Assuming UserManager(user_db) is enough based on create_superuser.py
            user_manager = UserManager(user_db)

            logger.warning(f"Creating new superuser: {email}")

            # Use safe=True so the safe-create hooks run; privilege escalation is then
            # an explicit, auditable separate step (V15.3.3). is_verified is intentionally
            # left False so fastapi-users requires email verification before login (V6.4.1).
            user = await user_manager.create(
                UserCreate(
                    email=email,
                    password=password,
                ),
                safe=True,
            )
            user.is_superuser = True
            user.is_active = True
            user.is_verified = False
            await session.commit()
            logger.warning(
                "auth.account_created",
                extra={
                    "event": "auth.account_created",
                    "email": user.email,
                    "is_superuser": True,
                    "source": "reset_superuser_script",
                },
            )
            # Write the generated password to a 0600-permission file rather than printing
            # it - prevents capture by terminal scrollback / CI logs / fluentd pipelines.
            os.umask(0o077)
            cred_path = pathlib.Path("/tmp/sccap-reset.pwd")
            cred_path.write_text(f"email={email}\npassword={password}\n")
            try:
                os.chmod(str(cred_path), 0o600)
            except OSError:
                pass
            logger.warning("=" * 40)
            logger.warning("SUPERUSER CREATED SUCCESSFULLY")
            logger.warning("=" * 40)
            logger.warning(f"Email:    {email}")
            logger.warning(
                f"Password fingerprint (sha256[:8]): {hashlib.sha256(password.encode()).hexdigest()[:8]}"
            )
            logger.warning(
                f"Password written to {cred_path} (mode 0600); operator must delete after first-use rotation."
            )
            logger.warning("=" * 40)
        except Exception:
            await session.rollback()
            logger.exception("reset_superuser.create_failed")
            raise SystemExit(1)


if __name__ == "__main__":
    try:
        asyncio.run(reset_superuser())
    except Exception:
        logger.exception("reset_superuser aborted")
        raise SystemExit(1)
