import asyncio
import sys
import os

# Add the project root to the python path
sys.path.append(os.getcwd())
sys.path.append(os.path.join(os.getcwd(), "src"))

from app.infrastructure.database.database import AsyncSessionLocal
from app.infrastructure.database.models import User
from app.infrastructure.auth.manager import UserManager
from app.infrastructure.auth.schemas import UserCreate
from fastapi_users.db import SQLAlchemyUserDatabase

async def create_superuser():
    async with AsyncSessionLocal() as session:
        user_db = SQLAlchemyUserDatabase(session, User)
        user_manager = UserManager(user_db)
        
        email = "admin@example.com"
        password = "adminpassword"
        
        try:
            user = await user_manager.create(
                UserCreate(
                    email=email,
                    password=password,
                    is_superuser=True,
                    is_active=True,
                    is_verified=True
                )
            )
            print(f"Superuser created successfully: {user.email}")
        except Exception as e:
            print(f"User creation skipped (might already exist): {e}")

if __name__ == "__main__":
    asyncio.run(create_superuser())
