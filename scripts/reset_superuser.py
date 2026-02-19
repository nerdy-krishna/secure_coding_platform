import asyncio
import sys
import os
import secrets
import string

# Add project root
sys.path.append(os.getcwd())
sys.path.append(os.path.join(os.getcwd(), "src"))

from sqlalchemy import delete
from app.infrastructure.database.database import AsyncSessionLocal
from app.infrastructure.database.models import User
from app.infrastructure.auth.manager import UserManager
from app.infrastructure.auth.schemas import UserCreate
from fastapi_users.db import SQLAlchemyUserDatabase

def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for i in range(length))

async def reset_superuser():
    async with AsyncSessionLocal() as session:
        # Delete all users
        print("Deleting all existing users...")
        await session.execute(delete(User))
        await session.commit()
        
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
        
        print(f"Creating new superuser: {email}")
        
        try:
            # We use safe=False to avoid needing a request/response context if the manager handles events
            user = await user_manager.create(
                UserCreate(
                    email=email,
                    password=password,
                    is_superuser=True,
                    is_active=True,
                    is_verified=True
                ),
                safe=False
            )
            print("\n" + "="*40)
            print("SUPERUSER CREATED SUCCESSFULLY")
            print("="*40)
            print(f"Email:    {email}")
            print(f"Password: {password}")
            print("="*40 + "\n")
        except Exception as e:
            print(f"Error creating superuser: {e}")

if __name__ == "__main__":
    asyncio.run(reset_superuser())
