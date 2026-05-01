"""DEV-ONLY smoke test for the /setup + CORS + admin/system-config flow.

DESTRUCTIVE: wipes 11 tables on every run.
Refuses to run unless SCCAP_ENV != 'prod' AND VERIFY_SETUP_OK=YES.

This script must never run against production. All credentials referenced here
must be throwaway test values supplied via environment variables:
  VERIFY_ADMIN_EMAIL   - test admin e-mail address
  VERIFY_ADMIN_PASSWORD - test admin password (throwaway only)
  VERIFY_LLM_API_KEY   - fake/test LLM API key
"""

import asyncio
import hashlib
import httpx
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
import sys
import os

# Adjust path to include src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from app.config.config import settings

# Database URL
DATABASE_URL = settings.ASYNC_DATABASE_URL


async def reset_db():
    # V02.3.2 / V15.1.5: refuse to run against non-localhost or production DB URLs
    db_url = DATABASE_URL or ""
    if "localhost" not in db_url and "127.0.0.1" not in db_url:
        raise RuntimeError(
            "reset_db refuses to run against a non-localhost DB URL. "
            "Ensure ASYNC_DATABASE_URL points to a local test database."
        )
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
        await conn.execute(text('DELETE FROM "user";'))
        await conn.execute(text("DELETE FROM system_configurations;"))
    print("Database reset complete.")
    await engine.dispose()


async def verify_setup_flow():
    # V13.2.3 / V13.3.1: read credentials from environment variables; abort if missing
    _missing = [
        v
        for v in ("VERIFY_ADMIN_EMAIL", "VERIFY_ADMIN_PASSWORD", "VERIFY_LLM_API_KEY")
        if not os.environ.get(v)
    ]
    if _missing:
        raise SystemExit(
            f"Missing required environment variables: {', '.join(_missing)}. "
            "Set them to throwaway test credentials before running this script. "
            "This script must NEVER run against production."
        )
    admin_email = os.environ["VERIFY_ADMIN_EMAIL"]
    admin_password = os.environ["VERIFY_ADMIN_PASSWORD"]
    llm_api_key = os.environ["VERIFY_LLM_API_KEY"]

    base_url = "http://localhost:8000/api/v1"

    async with httpx.AsyncClient(timeout=30.0) as client:
        # 1. Check Setup Status (Should be False)
        print("Checking setup status (Expect False)...")
        resp = await client.get(f"{base_url}/setup/status")
        # V14.2.4: do not print response body as it may echo sensitive setup data
        print(f"Status: {resp.status_code}")
        if resp.json().get("is_setup_completed") is not False:
            print("ERROR: Setup should be incomplete")
            return

        # 2. Perform Setup
        print("Performing Setup...")
        setup_payload = {
            "admin_email": admin_email,
            "admin_password": admin_password,
            "llm_provider": "openai",
            "llm_api_key": llm_api_key,
            "llm_model": "gpt-4o",
            "enable_cors": True,
            "allowed_origins": ["http://localhost:5173", "http://test-origin.com"],
        }
        resp = await client.post(f"{base_url}/setup", json=setup_payload)
        print(f"Setup Response: {resp.status_code}")
        if resp.status_code != 200:
            print(f"Error Body: {resp.text}")
            return
        # V14.2.4: assert structure without printing sensitive body (echoes admin_email / llm_api_key)
        setup_body = resp.json()
        assert isinstance(setup_body, dict), "Unexpected setup response format"
        if resp.status_code != 200:
            print("ERROR: Setup failed")
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
        # V13.2.3 / V13.3.1: credentials sourced from env vars resolved above
        login_data = {"username": admin_email, "password": admin_password}
        resp = await client.post(f"{base_url}/auth/login", data=login_data)
        if resp.status_code != 200:
            print("ERROR: Login failed")
            return
        token = resp.json()["access_token"]
        # V14.2.4: never print the raw token; log only its sha256 digest for audit trail
        token_digest = hashlib.sha256(token.encode()).hexdigest()
        print(f"Login Successful. Token digest (sha256): {token_digest}")

        # 7. Check Log Level Logic via API (needs logic in admin_logs or checking logs)
        # We can check the system config via admin API
        print("Checking System Config for Log Level...")
        headers = {"Authorization": f"Bearer {token}"}
        resp = await client.get(f"{base_url}/admin/system-config/", headers=headers)
        configs = resp.json()
        log_level_conf = next(
            (c for c in configs if c["key"] == "system.log_level"), None
        )
        print(f"Log Level Config: {log_level_conf}")
        if log_level_conf and log_level_conf["value"] == "INFO":
            print("SUCCESS: Log Level is INFO as expected.")
        else:
            print(f"FAILURE: Log Level is not INFO. Got: {log_level_conf}")


if __name__ == "__main__":
    # V15.1.5 / V15.2.3: fail closed — refuse to run in production or without explicit opt-in
    if os.environ.get("SCCAP_ENV") == "prod":
        raise SystemExit(
            "refusing: SCCAP_ENV is 'prod' — this destructive script must not run in production"
        )
    if os.environ.get("VERIFY_SETUP_OK") != "YES":
        raise SystemExit(
            "refusing: set VERIFY_SETUP_OK=YES and SCCAP_ENV != prod to run this script"
        )
    asyncio.run(reset_db())
    asyncio.run(verify_setup_flow())
