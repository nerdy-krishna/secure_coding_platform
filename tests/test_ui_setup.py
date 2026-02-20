import pytest
import os
from playwright.sync_api import Page, expect

def test_setup_flow(page: Page):
    page.on("console", lambda msg: print(f"BROWSER CONSOLE: {msg.type}: {msg.text}"))
    page.on("request", lambda req: print(f"BROWSER REQUEST: {req.method} {req.url}"))
    page.on("response", lambda res: print(f"BROWSER RESPONSE: {res.status} {res.url}"))

    # Navigate to setup page
    page.goto("http://localhost/setup")

    # Step 1: Deployment Environment
    page.wait_for_selector('label:has-text("Deployment Environment")')
    # Click Local Development
    page.click('h3:has-text("Local Development")')
    page.click('button:has-text("Next")')

    # Step 2: Admin
    page.wait_for_selector('label:has-text("Admin Email")')
    page.fill('input[name="admin_email"]', 'admin@example.com')
    page.fill('input[name="admin_password"]', 'securepassword123')
    page.click('button:has-text("Next")')

    # Step 3: LLM Config
    page.wait_for_selector('label:has-text("LLM Provider")')
    page.select_option('select[name="llm_provider"]', 'openai')
    page.fill('input[name="llm_model"]', 'gpt-4o')
    page.fill('input[name="llm_api_key"]', 'sk-test-key-12345')
    
    # Save a screenshot in the brain directory for walkthrough documentation
    brain_dir = "/Users/overlord/.gemini/antigravity/brain/d4e46eca-adbf-4fb6-b547-a673b4335ed0"
    page.screenshot(path=os.path.join(brain_dir, "setup_page_cors_step.png"))

    page.click('button:has-text("Finish Setup")')

    # Expect redirect to login page
    page.wait_for_url("**/login", timeout=10000)
    page.screenshot(path=os.path.join(brain_dir, "artifacts/login_page_after_setup.png"))
    expect(page.locator('h2:has-text("Login")')).to_be_visible()
