import pytest
import os
from playwright.sync_api import Page, expect

def test_setup_flow(page: Page):
    # Navigate to setup page
    page.goto("http://localhost:5173/setup")

    # Step 1: Admin
    page.wait_for_selector('h1:has-text("Secure Coding Platform Setup")')
    page.fill('input[name="admin_email"]', 'admin@example.com')
    page.fill('input[name="admin_password"]', 'securepassword123')
    page.click('button:has-text("Next")')

    # Step 2: LLM Config
    page.wait_for_selector('label:has-text("LLM Provider")')
    page.select_option('select[name="llm_provider"]', 'openai')
    page.fill('input[name="llm_model"]', 'gpt-4o')
    page.fill('input[name="llm_api_key"]', 'sk-test-key-12345')
    page.click('button:has-text("Next")')

    # Step 3: Deployment & CORS
    page.wait_for_selector('label:has-text("External Deployment / CORS")')
    # Check "Enable CORS"
    page.check('input[type="checkbox"]')
    
    # Wait for the origin input to appear and fill it
    page.wait_for_selector('input[placeholder*="https://"]')
    page.fill('input[placeholder*="https://"]', 'http://localhost:5173, http://127.0.0.1:5173')
    
    # Save a screenshot in the brain directory for walkthrough documentation
    brain_dir = "/Users/overlord/.gemini/antigravity/brain/d4e46eca-adbf-4fb6-b547-a673b4335ed0"
    page.screenshot(path=os.path.join(brain_dir, "setup_page_cors_step.png"))

    page.click('button:has-text("Finish Setup")')

    # Expect redirect to login page
    page.wait_for_url("**/login", timeout=10000)
    page.screenshot(path=os.path.join(brain_dir, "artifacts/login_page_after_setup.png"))
    expect(page.locator('h2:has-text("Login")')).to_be_visible()
