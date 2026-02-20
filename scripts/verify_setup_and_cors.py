import asyncio
import httpx
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
import sys
import os

# Adjust path to include src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from app.config.config import settings

# Database URL
DATABASE_URL = settings.ASYNC_DATABASE_URL

async def reset_db():
    print("Resetting database setup status...")
    engine = create_async_engine(DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        # Reset users and system configuration
        # Order matters due to foreign keys
        await conn.execute(text("DELETE FROM llm_interactions;"))
        await conn.execute(text("DELETE FROM chat_messages;"))
        await conn.execute(text("DELETE FROM chat_sessions;"))
        await conn.execute(text("DELETE FROM findings;"))
        await conn.execute(text("DELETE FROM scan_events;"))
        await conn.execute(text("DELETE FROM code_snapshots;"))
        await conn.execute(text("DELETE FROM scans;"))
        await conn.execute(text("DELETE FROM projects;"))
        await conn.execute(text("DELETE FROM llm_configurations;"))
        await conn.execute(text("DELETE FROM \"user\";"))
        await conn.execute(text("DELETE FROM system_configurations;"))
    print("Database reset complete.")
    await engine.dispose()

async def verify_setup_flow():
    base_url = "http://localhost:8000/api/v1"
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        # 1. Check Setup Status (Should be False)
        print("Checking setup status (Expect False)...")
        resp = await client.get(f"{base_url}/setup/status")
        print(f"Status: {resp.status_code}, Body: {resp.text}")
        if resp.json().get("is_setup_completed") is not False:
            print("ERROR: Setup should be incomplete")
            return

        # 2. Perform Setup
        print("Performing Setup...")
        setup_payload = {
            "admin_email": "admin@example.com",
            "admin_password": "SecurePassword123!",
            "llm_provider": "openai",
            "llm_api_key": "sk-fake-key",
            "llm_model": "gpt-4o",
            "enable_cors": True,
            "allowed_origins": ["http://localhost:5173", "http://test-origin.com"]
        }
        resp = await client.post(f"{base_url}/setup", json=setup_payload)
        print(f"Setup Response: {resp.status_code}")
        if resp.status_code != 200:
             print(f"Error Body: {resp.text}")
             return
        print(f"Body: {resp.json()}")
        if resp.status_code != 200:
            print(f"ERROR: Setup failed: {resp.text}")
            return

        # 3. Check Setup Status (Should be True)
        print("Checking setup status (Expect True)...")
        resp = await client.get(f"{base_url}/setup/status")
        print(f"Status: {resp.json()}")
        if resp.json().get("is_setup_completed") is not True:
            print("ERROR: Setup should be complete")
            return

        # 4. Verify CORS for allowed origin
        print("Verifying CORS for allowed origin...")
        headers = {"Origin": "http://test-origin.com"}
        resp = await client.options(f"{base_url}/setup/status", headers=headers)
        if resp.headers.get("access-control-allow-origin") == "http://test-origin.com":
            print("SUCCESS: CORS Allowed Origin Check Passed")
        else:
            print(f"FAILURE: CORS Header Missing or Wrong: {resp.headers}")

        # 5. Verify CORS for disallowed origin
        print("Verifying CORS for disallowed origin...")
        headers = {"Origin": "http://evil.com"}
        resp = await client.options(f"{base_url}/setup/status", headers=headers)
        if "access-control-allow-origin" not in resp.headers:
            print("SUCCESS: CORS Disallowed Origin Check Passed (No Header)")
        else:
            print(f"FAILURE: CORS Header Present for Disallowed Origin: {resp.headers}")

        # 6. Login to get token
        print("Logging in...")
        login_data = {"username": "admin@example.com", "password": "SecurePassword123!"}
        resp = await client.post(f"{base_url}/auth/login", data=login_data)
        if resp.status_code != 200:
             print("ERROR: Login failed")
             return
        token = resp.json()["access_token"]
        print("Login Successful.")

        # 7. Check Log Level Logic via API (needs logic in admin_logs or checking logs)
        # We can check the system config via admin API
        print("Checking System Config for Log Level...")
        headers = {"Authorization": f"Bearer {token}"}
        resp = await client.get(f"{base_url}/admin/system-config/", headers=headers)
        configs = resp.json()
        log_level_conf = next((c for c in configs if c["key"] == "system.log_level"), None)
        print(f"Log Level Config: {log_level_conf}")
        if log_level_conf and log_level_conf["value"] == "INFO":
             print("SUCCESS: Log Level is INFO as expected.")
        else:
             print(f"FAILURE: Log Level is not INFO. Got: {log_level_conf}")

if __name__ == "__main__":
    asyncio.run(reset_db())
    asyncio.run(verify_setup_flow())
