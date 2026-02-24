import asyncio
import sys
import os

# Add project root
sys.path.append(os.getcwd())
sys.path.append(os.path.join(os.getcwd(), "src"))

from sqlalchemy import text
from app.infrastructure.database.database import AsyncSessionLocal

async def reset_app():
    async with AsyncSessionLocal() as session:
        print("Resetting database...")
        # Truncate core tables with CASCADE to wipe all related data (projects, scans, etc.)
        tables = [
            "system_configurations",
            "llm_configurations",
            "\"user\""
        ]
        
        for table in tables:
            try:
                await session.execute(text(f"TRUNCATE TABLE {table} CASCADE;"))
                print(f"Truncated {table} with CASCADE")
            except Exception as e:
                print(f"Error truncating {table}: {e}")
                
        await session.commit()
        print("Database reset successfully.")

if __name__ == "__main__":
    asyncio.run(reset_app())
