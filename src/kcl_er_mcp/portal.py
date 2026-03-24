"""KCL e-Research Portal API client.

All operations use httpx against reverse-engineered Laravel endpoints.
Session management is delegated to auth.SessionManager (auto-login on expiry).

Endpoints:
  GET  /mfa                        → HTML table of MFA entries
  POST /api/internal/mfa/approve   → Approve IP (_token, service, ip_address)
  POST /api/internal/mfa/reject    → Reject/Revoke IP (_token, service, ip_address)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Optional

import httpx

from kcl_er_mcp.auth import SessionManager, SessionError

logger = logging.getLogger(__name__)

PORTAL_BASE = "https://portal.er.kcl.ac.uk"
MFA_URL = f"{PORTAL_BASE}/mfa"
MFA_APPROVE_URL = f"{PORTAL_BASE}/api/internal/mfa/approve"
MFA_REJECT_URL = f"{PORTAL_BASE}/api/internal/mfa/reject"
SSO_DOMAIN = "login.microsoftonline.com"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class MFAEntry:
    service: str          # "ssh" | "openvpn"
    ip_address: str
    location: str = ""
    last_updated: str = ""
    expiry: str = ""
    status: str = ""      # "approved" | "pending"

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "ip_address": self.ip_address,
            "location": self.location,
            "last_updated": self.last_updated,
            "expiry": self.expiry,
            "status": self.status,
        }


# ---------------------------------------------------------------------------
# HTML Parsers (stdlib — no external deps)
# ---------------------------------------------------------------------------

class _CSRFParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.csrf_token: Optional[str] = None

    def handle_starttag(self, tag, attrs):
        if tag == "meta":
            d = dict(attrs)
            if d.get("name") == "csrf-token":
                self.csrf_token = d.get("content", "")


class _MFATableParser(HTMLParser):
    """Parse the /mfa HTML table.

    Columns: Service | Remote IP | Location | Last updated | Expiry | Status | Action
    Extracts hidden input values (service, ip_address) from action forms.
    """

    def __init__(self):
        super().__init__()
        self.entries: list[MFAEntry] = []
        self._in_tbody = False
        self._in_tr = False
        self._in_td = False
        self._row: list[str] = []
        self._cell = ""
        self._form_service = ""
        self._form_ip = ""

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "tbody":
            self._in_tbody = True
        elif tag == "tr" and self._in_tbody:
            self._in_tr = True
            self._row = []
            self._cell = ""
            self._form_service = ""
            self._form_ip = ""
        elif tag == "td" and self._in_tr:
            self._in_td = True
            self._cell = ""
        elif tag == "input" and self._in_tr:
            name = d.get("name", "")
            val = d.get("value", "")
            if name == "service":
                self._form_service = val
            elif name == "ip_address":
                self._form_ip = val

    def handle_endtag(self, tag):
        if tag == "tbody":
            self._in_tbody = False
        elif tag == "tr" and self._in_tr:
            self._in_tr = False
            if len(self._row) >= 6:
                self.entries.append(MFAEntry(
                    service=self._form_service or self._row[0].strip().lower(),
                    ip_address=self._form_ip or self._row[1].strip(),
                    location=self._row[2].strip(),
                    last_updated=self._row[3].strip(),
                    expiry=self._row[4].strip(),
                    status=self._row[5].strip().lower(),
                ))
        elif tag == "td" and self._in_td:
            self._in_td = False
            self._row.append(self._cell)

    def handle_data(self, data):
        if self._in_td:
            self._cell += data


class _FlashParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self._in_alert = False
        self._alert_type = ""
        self._text = ""
        self.messages: list[dict[str, str]] = []

    def handle_starttag(self, tag, attrs):
        if tag == "div":
            cls = dict(attrs).get("class", "")
            if "alert-success" in cls:
                self._in_alert, self._alert_type, self._text = True, "success", ""
            elif "alert-danger" in cls or "alert-warning" in cls:
                self._in_alert, self._alert_type, self._text = True, "error", ""

    def handle_endtag(self, tag):
        if tag == "div" and self._in_alert:
            self._in_alert = False
            if self._text.strip():
                self.messages.append({"type": self._alert_type, "message": self._text.strip()})

    def handle_data(self, data):
        if self._in_alert:
            self._text += data


# ---------------------------------------------------------------------------
# Portal Client
# ---------------------------------------------------------------------------

class PortalClient:
    """Portal API client — all ops via httpx, auto-login via SessionManager."""

    def __init__(self, session_manager: SessionManager) -> None:
        self._sm = session_manager
        self._http: Optional[httpx.AsyncClient] = None

    def _build_client(self) -> httpx.AsyncClient:
        """Create httpx client with current session cookies."""
        s = self._sm.session
        cookies = httpx.Cookies()
        if s.laravel_session:
            cookies.set("e_research_portal_session", s.laravel_session, domain="portal.er.kcl.ac.uk")
        if s.xsrf_token:
            cookies.set("XSRF-TOKEN", s.xsrf_token, domain="portal.er.kcl.ac.uk")
        return httpx.AsyncClient(
            cookies=cookies,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Referer": MFA_URL,
            },
            follow_redirects=True,
            timeout=30.0,
        )

    async def _ensure_session(self) -> None:
        """Ensure we have a valid session, auto-login if needed."""
        await self._sm.get_valid_session()

    async def _get_mfa_page(self) -> str:
        """GET /mfa — refresh CSRF token and return HTML.

        Detects SSO redirect (session expired) and triggers re-login.
        """
        async with self._build_client() as client:
            resp = await client.get(MFA_URL)

        # Detect SSO redirect → session expired
        if SSO_DOMAIN in str(resp.url):
            logger.info("Session expired (SSO redirect), re-logging in...")
            self._sm.invalidate_session()
            result = await self._sm.login()
            if not result.get("success"):
                raise SessionError(f"Re-login failed: {result.get('error')}")
            # Retry with fresh session
            async with self._build_client() as client:
                resp = await client.get(MFA_URL)
                if SSO_DOMAIN in str(resp.url):
                    raise SessionError("Still redirecting to SSO after re-login.")

        resp.raise_for_status()
        html = resp.text

        # Update CSRF token
        p = _CSRFParser()
        p.feed(html)
        if p.csrf_token:
            self._sm.session.csrf_token = p.csrf_token

        # Update cookies if server rotated them
        for c in resp.cookies.jar:
            if c.name == "XSRF-TOKEN":
                self._sm.session.xsrf_token = c.value
            elif c.name == "e_research_portal_session":
                self._sm.session.laravel_session = c.value
        self._sm._save_session()

        return html

    async def _post(self, url: str, data: dict) -> httpx.Response:
        """POST with CSRF token and session cookies."""
        csrf = self._sm.session.csrf_token
        async with self._build_client() as client:
            resp = await client.post(
                url,
                data={"_token": csrf, **data},
                headers={
                    "X-CSRF-TOKEN": csrf,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
        # Update cookies
        for c in resp.cookies.jar:
            if c.name == "XSRF-TOKEN":
                self._sm.session.xsrf_token = c.value
            elif c.name == "e_research_portal_session":
                self._sm.session.laravel_session = c.value
        self._sm._save_session()
        return resp

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get_mfa_entries(self) -> list[MFAEntry]:
        """Get all MFA entries from the portal."""
        await self._ensure_session()
        html = await self._get_mfa_page()
        p = _MFATableParser()
        p.feed(html)
        logger.info("Parsed %d MFA entries", len(p.entries))
        return p.entries

    async def get_pending(self) -> list[MFAEntry]:
        """Get only pending MFA requests."""
        entries = await self.get_mfa_entries()
        return [e for e in entries if e.status == "pending"]

    async def approve_ip(self, ip_address: str, service: str = "ssh") -> dict:
        """Approve an IP via POST /api/internal/mfa/approve. Idempotent."""
        await self._ensure_session()
        await self._get_mfa_page()  # Refresh CSRF
        resp = await self._post(MFA_APPROVE_URL, {
            "service": service,
            "ip_address": ip_address,
        })
        flash = _FlashParser()
        flash.feed(resp.text)
        ok = any(m["type"] == "success" for m in flash.messages)
        return {
            "success": ok or resp.status_code in (200, 302),
            "ip_address": ip_address,
            "service": service,
            "messages": flash.messages,
        }

    async def reject_ip(self, ip_address: str, service: str = "ssh") -> dict:
        """Revoke/reject an IP via POST /api/internal/mfa/reject."""
        await self._ensure_session()
        await self._get_mfa_page()
        resp = await self._post(MFA_REJECT_URL, {
            "service": service,
            "ip_address": ip_address,
        })
        flash = _FlashParser()
        flash.feed(resp.text)
        ok = any(m["type"] == "success" for m in flash.messages)
        return {
            "success": ok or resp.status_code in (200, 302),
            "ip_address": ip_address,
            "service": service,
            "messages": flash.messages,
        }

    async def approve_all_pending(self) -> list[dict]:
        """Approve ALL pending MFA requests in one go."""
        pending = await self.get_pending()
        if not pending:
            return [{"message": "No pending MFA requests"}]
        results = []
        for entry in pending:
            r = await self.approve_ip(entry.ip_address, entry.service)
            results.append(r)
        return results

    async def approve_current_ip(self, service: str = "ssh") -> dict:
        """Auto-detect current public IP and approve it."""
        ip = await get_current_ip()
        result = await self.approve_ip(ip, service)
        result["detected_ip"] = ip
        return result

    async def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

async def get_current_ip() -> str:
    """Get current public IP address."""
    async with httpx.AsyncClient(timeout=10) as client:
        for url in [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://checkip.amazonaws.com",
        ]:
            try:
                resp = await client.get(url)
                return resp.text.strip()
            except Exception:
                continue
    return "unknown"
