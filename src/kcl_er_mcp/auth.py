"""Fully automated SSO login for KCL e-Research Portal.

Flow: Playwright headless → Microsoft SSO → email/password → TOTP → portal session

Credentials from environment variables:
  KCL_EMAIL          k-number@kcl.ac.uk
  KCL_PASSWORD       KCL account password
  KCL_TOTP_SECRET    TOTP secret (base32, from authenticator app setup)

Session persisted to ~/.kcl-er-mcp/session.json for reuse across restarts.
Auto-re-login when session expires (~2h).
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pyotp

logger = logging.getLogger(__name__)

STATE_DIR = Path.home() / ".kcl-er-mcp"
SESSION_FILE = STATE_DIR / "session.json"
BROWSER_STATE_DIR = STATE_DIR / "browser-state"

PORTAL_BASE = "https://portal.er.kcl.ac.uk"
SSO_DOMAIN = "login.microsoftonline.com"


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

@dataclass
class SessionState:
    """Portal session cookies + CSRF token."""
    laravel_session: str = ""
    xsrf_token: str = ""
    csrf_token: str = ""
    obtained_at: Optional[str] = None

    def is_valid(self) -> bool:
        return bool(self.laravel_session and self.xsrf_token)

    def to_dict(self) -> dict:
        return {
            "laravel_session": self.laravel_session,
            "xsrf_token": self.xsrf_token,
            "csrf_token": self.csrf_token,
            "obtained_at": self.obtained_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> SessionState:
        return cls(**{k: d.get(k, "") for k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Credential loading
# ---------------------------------------------------------------------------

def _get_credentials() -> tuple[str, str, str]:
    """Load credentials from environment variables.

    Returns (email, password, totp_secret).
    Raises ValueError if any are missing.
    """
    email = os.environ.get("KCL_EMAIL", "")
    password = os.environ.get("KCL_PASSWORD", "")
    totp_secret = os.environ.get("KCL_TOTP_SECRET", "")

    missing = []
    if not email:
        missing.append("KCL_EMAIL")
    if not password:
        missing.append("KCL_PASSWORD")
    if not totp_secret:
        missing.append("KCL_TOTP_SECRET")

    if missing:
        raise ValueError(
            f"Missing environment variables: {', '.join(missing)}. "
            "Set them before running the server:\n"
            '  export KCL_EMAIL="k1234567@kcl.ac.uk"\n'
            '  export KCL_PASSWORD="your_password"\n'
            '  export KCL_TOTP_SECRET="your_totp_base32_secret"'
        )
    return email, password, totp_secret


# ---------------------------------------------------------------------------
# Session Manager
# ---------------------------------------------------------------------------

class SessionManager:
    """Manages portal authentication lifecycle.

    - Loads/saves session from disk
    - Auto-logs in via Playwright when session is missing or expired
    - Provides session cookies for httpx API calls
    """

    def __init__(self) -> None:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        BROWSER_STATE_DIR.mkdir(parents=True, exist_ok=True)
        self._session = self._load_session()
        self._pw = None
        self._browser = None

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    @staticmethod
    def _load_session() -> SessionState:
        if SESSION_FILE.exists():
            try:
                data = json.loads(SESSION_FILE.read_text())
                s = SessionState.from_dict(data)
                if s.is_valid():
                    logger.info("Loaded session (obtained: %s)", s.obtained_at)
                    return s
            except (json.JSONDecodeError, OSError):
                pass
        return SessionState()

    def _save_session(self) -> None:
        SESSION_FILE.write_text(json.dumps(self._session.to_dict(), indent=2))

    @property
    def session(self) -> SessionState:
        return self._session

    # ------------------------------------------------------------------
    # Automated SSO Login
    # ------------------------------------------------------------------

    async def login(self) -> dict:
        """Fully automated SSO login via Playwright.

        Flow:
          1. Navigate to portal → redirect to login.microsoftonline.com
          2. Enter email (or select cached account)
          3. Enter password
          4. Enter TOTP code (pyotp)
          5. Handle "Stay signed in?" prompt
          6. Wait for redirect back to portal
          7. Extract laravel_session + XSRF-TOKEN + csrf-token

        Returns dict with success status and details.
        """
        from playwright.async_api import async_playwright

        email, password, totp_secret = _get_credentials()
        totp = pyotp.TOTP(totp_secret)

        self._pw = await async_playwright().start()
        browser = await self._pw.chromium.launch(
            headless=os.environ.get("KCL_ER_HEADLESS", "1") == "1",
        )

        state_file = BROWSER_STATE_DIR / "state.json"
        context = await browser.new_context(
            storage_state=str(state_file) if state_file.exists() else None,
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
        )
        page = await context.new_page()

        try:
            # Step 1: Navigate to portal
            logger.info("Navigating to portal...")
            await page.goto(PORTAL_BASE, wait_until="networkidle", timeout=30_000)

            # Step 2: Check if SSO login needed
            if SSO_DOMAIN in page.url:
                logger.info("SSO login page detected, automating...")

                # Step 2a: Email / account selection
                try:
                    # Check for cached account tile
                    account_tile = page.locator(f'div[data-test-id="{email}"]')
                    if await account_tile.count() > 0:
                        await account_tile.click()
                        logger.info("Selected cached account")
                    else:
                        email_input = page.locator(
                            'input[type="email"][name="loginfmt"]'
                        )
                        await email_input.wait_for(state="visible", timeout=5_000)
                        await email_input.fill(email)
                        await page.locator(
                            'input[type="submit"][value="Next"], #idSIButton9'
                        ).click()
                        logger.info("Entered email")
                except Exception:
                    logger.debug("Email step skipped (may be cached)")

                # Step 2b: Password
                try:
                    pw_input = page.locator(
                        'input[type="password"][name="passwd"]'
                    )
                    await pw_input.wait_for(state="visible", timeout=10_000)
                    await pw_input.fill(password)
                    await page.locator(
                        'input[type="submit"][value="Sign in"], #idSIButton9'
                    ).click()
                    logger.info("Entered password")
                except Exception:
                    logger.debug("Password step skipped (may be cached)")

                # Step 2c: TOTP verification
                try:
                    otp_input = page.locator(
                        'input#idTxtBx_SAOTCC_OTC, input[name="otc"]'
                    )
                    await otp_input.wait_for(state="visible", timeout=15_000)
                    code = totp.now()
                    await otp_input.fill(code)
                    await page.locator(
                        '#idSubmit_SAOTCC_Continue, '
                        'input[type="submit"][value="Verify"]'
                    ).click()
                    logger.info("Entered TOTP code")
                except Exception:
                    logger.debug("TOTP step skipped (may not be required)")

                # Step 2d: "Stay signed in?" prompt
                try:
                    yes_btn = page.locator('#idSIButton9, input[value="Yes"]')
                    await yes_btn.wait_for(state="visible", timeout=5_000)
                    await yes_btn.click()
                    logger.info("Clicked 'Stay signed in'")
                except Exception:
                    logger.debug("Stay-signed-in prompt skipped")

            # Step 3: Wait for portal redirect
            portal_host = PORTAL_BASE.split("//")[-1]
            await page.wait_for_url(f"**/{portal_host}/**", timeout=30_000)
            logger.info("Redirected back to portal")

            # Step 4: Ensure we're on MFA page (triggers session fully)
            await page.goto(f"{PORTAL_BASE}/mfa", wait_until="networkidle", timeout=15_000)

            # Step 5: Extract cookies
            cookies = await context.cookies()
            cookie_dict = {}
            for c in cookies:
                if "portal.er.kcl.ac.uk" in c.get("domain", ""):
                    cookie_dict[c["name"]] = c["value"]

            laravel_session = cookie_dict.get("e_research_portal_session", "") or cookie_dict.get("laravel_session", "")
            xsrf_token = cookie_dict.get("XSRF-TOKEN", "")

            if not laravel_session:
                await page.screenshot(
                    path=str(STATE_DIR / "login_error.png"), full_page=True
                )
                return {
                    "success": False,
                    "error": "Could not extract laravel_session. Screenshot saved.",
                }

            # Step 6: Extract CSRF token
            csrf_token = await page.evaluate(
                """() => document.querySelector('meta[name="csrf-token"]')?.content || ''"""
            )

            # Save
            self._session = SessionState(
                laravel_session=laravel_session,
                xsrf_token=xsrf_token,
                csrf_token=csrf_token,
                obtained_at=datetime.now(timezone.utc).isoformat(),
            )
            self._save_session()
            await context.storage_state(path=str(state_file))

            logger.info("Login successful, session saved")
            return {
                "success": True,
                "session_obtained": self._session.obtained_at,
            }

        except Exception as e:
            try:
                await page.screenshot(
                    path=str(STATE_DIR / "login_error.png"), full_page=True
                )
            except Exception:
                pass
            return {"success": False, "error": str(e)}

        finally:
            await browser.close()
            await self._pw.stop()
            self._pw = None

    # ------------------------------------------------------------------
    # Session access (auto-refresh)
    # ------------------------------------------------------------------

    async def get_valid_session(self) -> SessionState:
        """Get a valid session, logging in automatically if needed.

        This is the main entry point for other modules — just call this
        and you'll get working cookies, or an exception if login fails.
        """
        if self._session.is_valid():
            return self._session

        logger.info("No valid session, attempting auto-login...")
        result = await self.login()
        if result.get("success"):
            return self._session
        raise SessionError(
            f"Auto-login failed: {result.get('error', 'unknown')}. "
            "Check credentials (KCL_EMAIL, KCL_PASSWORD, KCL_TOTP_SECRET)."
        )

    def invalidate_session(self) -> None:
        """Mark current session as invalid (triggers re-login on next use)."""
        self._session = SessionState()
        if SESSION_FILE.exists():
            SESSION_FILE.unlink(missing_ok=True)
        logger.info("Session invalidated")

    async def close(self) -> None:
        """Clean up resources."""
        pass  # Browser is cleaned in login() finally block


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SessionError(Exception):
    """Authentication or session error."""
    pass
