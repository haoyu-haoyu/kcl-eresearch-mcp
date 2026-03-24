"""KCL e-Research MCP Server — fully automated.

Zero-intervention MFA management for CREATE HPC:
  - Auto SSO login (Playwright + TOTP) when session expires
  - MFA approve/reject via Laravel API (httpx, ~50ms per call)
  - VPN tunnel management for stable IP
  - SSH with ControlMaster for connection reuse

Usage:
  export KCL_EMAIL="k1234567@kcl.ac.uk"
  export KCL_PASSWORD="your_password"
  export KCL_TOTP_SECRET="your_base32_totp_secret"
  claude mcp add kcl-er -- python -m kcl_er_mcp.server
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict

from kcl_er_mcp.auth import SessionManager, SessionError
from kcl_er_mcp.portal import PortalClient, get_current_ip
from kcl_er_mcp.vpn import VPNManager
from kcl_er_mcp.ssh_helper import SSHHelper

logging.basicConfig(
    level=os.environ.get("KCL_ER_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("kcl_er_mcp")


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app):
    sm = SessionManager()
    portal = PortalClient(sm)
    vpn = VPNManager()
    ssh = SSHHelper()
    yield {"sm": sm, "portal": portal, "vpn": vpn, "ssh": ssh}
    await sm.close()
    await portal.close()


mcp = FastMCP("kcl_er_mcp", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------

class EmptyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ApproveInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    ip_address: Optional[str] = Field(default=None, description="IP to approve. Omit to auto-detect current IP.", pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    service: str = Field(default="ssh", description="'ssh' or 'openvpn'", pattern=r"^(ssh|openvpn)$")


class RevokeInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    ip_address: str = Field(..., description="IP to revoke", pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    service: str = Field(default="ssh", pattern=r"^(ssh|openvpn)$")


class SSHCommandInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    command: str = Field(..., description="Command to run on CREATE", min_length=1, max_length=2000)
    timeout: int = Field(default=60, ge=5, le=600)


class SCPInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    remote_path: str = Field(..., description="Path on CREATE HPC")
    local_path: str = Field(..., description="Path on local machine")
    direction: str = Field(default="download", pattern=r"^(download|upload)$")
    timeout: int = Field(default=300, ge=30, le=3600)


class VPNConfigInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    config_path: Optional[str] = Field(default=None, description="Path to .ovpn file")


# Helpers for safe tool execution
def _ctx_get(ctx, key):
    return ctx.request_context.lifespan_state.get(key) if ctx else None


async def _safe(coro, error_prefix="") -> str:
    try:
        result = await coro
        return json.dumps(result, indent=2) if isinstance(result, (dict, list)) else str(result)
    except SessionError as e:
        return json.dumps({"error": "session_error", "message": str(e)}, indent=2)
    except Exception as e:
        return json.dumps({"error": error_prefix or "error", "message": str(e)}, indent=2)


# ===========================================================================
# Auth Tools
# ===========================================================================

@mcp.tool(name="er_login", annotations={"title": "Login to Portal", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
async def er_login(params: EmptyInput, ctx=None) -> str:
    """Force SSO re-login to the e-Research portal.

    Normally login is automatic (triggered when session expires).
    Use this only if auto-login fails or you need to refresh credentials.

    Runs headless Playwright: email → password → TOTP → session saved.
    Credentials from env vars: KCL_EMAIL, KCL_PASSWORD, KCL_TOTP_SECRET.
    """
    sm: SessionManager = _ctx_get(ctx, "sm") or SessionManager()
    return await _safe(sm.login())


@mcp.tool(name="er_session_check", annotations={"title": "Check Session", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
async def er_session_check(params: EmptyInput, ctx=None) -> str:
    """Check if portal session is valid. Tests by fetching /mfa page."""
    portal: PortalClient = _ctx_get(ctx, "portal") or PortalClient(SessionManager())
    try:
        entries = await portal.get_mfa_entries()
        return json.dumps({"valid": True, "entries_count": len(entries)})
    except SessionError as e:
        return json.dumps({"valid": False, "reason": str(e)})
    except Exception as e:
        return json.dumps({"valid": False, "reason": str(e)})


# ===========================================================================
# MFA Tools
# ===========================================================================

@mcp.tool(name="er_mfa_status", annotations={"title": "MFA Status", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
async def er_mfa_status(params: EmptyInput, ctx=None) -> str:
    """List all MFA entries (approved + pending) and check current IP status.

    Auto-logs in if session expired. Returns entries with service, IP,
    location, expiry, status. Highlights whether your current IP is approved.
    """
    portal: PortalClient = _ctx_get(ctx, "portal") or PortalClient(SessionManager())
    current_ip = await get_current_ip()
    try:
        entries = await portal.get_mfa_entries()
        approved = {e.ip_address for e in entries if e.status == "approved"}
        pending = {e.ip_address for e in entries if e.status == "pending"}
        if current_ip in approved:
            ip_status = "APPROVED"
        elif current_ip in pending:
            ip_status = "PENDING — run er_mfa_approve"
        else:
            ip_status = "NOT FOUND — run er_mfa_approve to add"
        return json.dumps({
            "current_ip": current_ip,
            "current_ip_status": ip_status,
            "entries": [e.to_dict() for e in entries],
            "counts": {"approved": len(approved), "pending": len(pending)},
        }, indent=2)
    except SessionError as e:
        return json.dumps({"current_ip": current_ip, "error": "session_error", "message": str(e)}, indent=2)


@mcp.tool(name="er_mfa_approve", annotations={"title": "Approve IP", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
async def er_mfa_approve(params: ApproveInput, ctx=None) -> str:
    """Approve an IP for SSH/VPN access to CREATE.

    If ip_address omitted, auto-detects current public IP.
    Calls POST /api/internal/mfa/approve. Idempotent.
    Auto-logs in if session expired.
    """
    portal: PortalClient = _ctx_get(ctx, "portal") or PortalClient(SessionManager())
    if params.ip_address:
        return await _safe(portal.approve_ip(params.ip_address, params.service))
    return await _safe(portal.approve_current_ip(params.service))


@mcp.tool(name="er_mfa_approve_all", annotations={"title": "Approve All Pending", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
async def er_mfa_approve_all(params: EmptyInput, ctx=None) -> str:
    """Approve ALL pending MFA requests in one shot.

    Fetches pending list, then approves each one via API.
    Perfect for when mobile hotspot triggered multiple MFA requests.
    """
    portal: PortalClient = _ctx_get(ctx, "portal") or PortalClient(SessionManager())
    return await _safe(portal.approve_all_pending())


@mcp.tool(name="er_mfa_revoke", annotations={"title": "Revoke IP", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True})
async def er_mfa_revoke(params: RevokeInput, ctx=None) -> str:
    """Revoke an approved/pending IP from MFA."""
    portal: PortalClient = _ctx_get(ctx, "portal") or PortalClient(SessionManager())
    return await _safe(portal.reject_ip(params.ip_address, params.service))


# ===========================================================================
# VPN Tools
# ===========================================================================

@mcp.tool(name="er_vpn_status", annotations={"title": "VPN Status", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def er_vpn_status(params: EmptyInput, ctx=None) -> str:
    """Check OpenVPN connection to bastion.er.kcl.ac.uk."""
    vpn: VPNManager = _ctx_get(ctx, "vpn") or VPNManager()
    status = await vpn.status()
    r = status.to_dict()
    r["public_ip"] = await get_current_ip()
    cfg = vpn.find_config()
    r["config_found"] = str(cfg) if cfg else None
    return json.dumps(r, indent=2)


@mcp.tool(name="er_vpn_connect", annotations={"title": "Connect VPN", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
async def er_vpn_connect(params: VPNConfigInput, ctx=None) -> str:
    """Start OpenVPN tunnel. Requires openvpn + sudo."""
    vpn: VPNManager = _ctx_get(ctx, "vpn") or VPNManager()
    status = await vpn.connect(params.config_path)
    return json.dumps(status.to_dict(), indent=2)


@mcp.tool(name="er_vpn_disconnect", annotations={"title": "Disconnect VPN", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def er_vpn_disconnect(params: EmptyInput, ctx=None) -> str:
    """Stop OpenVPN tunnel."""
    vpn: VPNManager = _ctx_get(ctx, "vpn") or VPNManager()
    status = await vpn.disconnect()
    return json.dumps(status.to_dict(), indent=2)


@mcp.tool(name="er_vpn_log", annotations={"title": "VPN Log", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def er_vpn_log(params: EmptyInput, ctx=None) -> str:
    """Last 50 lines of OpenVPN log."""
    vpn: VPNManager = _ctx_get(ctx, "vpn") or VPNManager()
    return vpn.get_log_tail(50)


# ===========================================================================
# SSH Tools
# ===========================================================================

@mcp.tool(name="er_ssh_test", annotations={"title": "Test SSH", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
async def er_ssh_test(params: EmptyInput, ctx=None) -> str:
    """Test SSH to CREATE. Diagnoses MFA issues if connection fails."""
    ssh: SSHHelper = _ctx_get(ctx, "ssh") or SSHHelper()
    r = await ssh.test_connection()
    d = r.to_dict()
    if r.mfa_needed:
        d["suggestion"] = "MFA needed. Run er_mfa_approve or er_vpn_connect."
    return json.dumps(d, indent=2)


@mcp.tool(name="er_ssh_run", annotations={"title": "Run on CREATE", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
async def er_ssh_run(params: SSHCommandInput, ctx=None) -> str:
    """Execute a command on CREATE HPC via SSH."""
    ssh: SSHHelper = _ctx_get(ctx, "ssh") or SSHHelper()
    r = await ssh.run_command(params.command, timeout=params.timeout)
    d = r.to_dict()
    if r.mfa_needed:
        d["suggestion"] = "Run er_mfa_approve or er_vpn_connect first."
    return json.dumps(d, indent=2)


@mcp.tool(name="er_scp_transfer", annotations={"title": "SCP Transfer", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
async def er_scp_transfer(params: SCPInput, ctx=None) -> str:
    """Transfer files between local and CREATE."""
    ssh: SSHHelper = _ctx_get(ctx, "ssh") or SSHHelper()
    if params.direction == "download":
        r = await ssh.scp_download(params.remote_path, params.local_path, params.timeout)
    else:
        r = await ssh.scp_upload(params.local_path, params.remote_path, params.timeout)
    return json.dumps(r.to_dict(), indent=2)


@mcp.tool(name="er_ssh_setup", annotations={"title": "Setup SSH", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def er_ssh_setup(params: EmptyInput, ctx=None) -> str:
    """Add ControlMaster config to ~/.ssh/config for CREATE."""
    ssh: SSHHelper = _ctx_get(ctx, "ssh") or SSHHelper()
    result = ssh.ensure_ssh_config()
    cm = await ssh.check_control_master()
    return json.dumps({"config_result": result, "control_master": cm}, indent=2)


# ===========================================================================
# Utility
# ===========================================================================

@mcp.tool(name="er_current_ip", annotations={"title": "Current IP", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
async def er_current_ip(params: EmptyInput) -> str:
    """Get current public IP."""
    return json.dumps({"ip": await get_current_ip()})


@mcp.tool(name="er_diagnose", annotations={"title": "Diagnose", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
async def er_diagnose(params: EmptyInput, ctx=None) -> str:
    """Full connectivity diagnostic: IP → session → VPN → SSH → MFA.

    Returns structured report with specific fix recommendations.
    """
    portal: PortalClient = _ctx_get(ctx, "portal") or PortalClient(SessionManager())
    vpn: VPNManager = _ctx_get(ctx, "vpn") or VPNManager()
    ssh: SSHHelper = _ctx_get(ctx, "ssh") or SSHHelper()

    report = {"checks": [], "recommendations": []}

    ip = await get_current_ip()
    report["checks"].append({"name": "Public IP", "value": ip})

    # Session
    try:
        entries = await portal.get_mfa_entries()
        report["checks"].append({"name": "Portal session", "valid": True})
        approved_ips = {e.ip_address for e in entries if e.status == "approved"}
        pending = [e for e in entries if e.status == "pending"]
        ip_ok = ip in approved_ips
        report["checks"].append({
            "name": "MFA", "current_ip_approved": ip_ok,
            "approved": len(approved_ips), "pending": len(pending),
        })
        if not ip_ok:
            report["recommendations"].append(f"IP {ip} not approved. Run er_mfa_approve.")
        if pending:
            report["recommendations"].append(f"{len(pending)} pending requests. Run er_mfa_approve_all.")
    except SessionError as e:
        report["checks"].append({"name": "Portal session", "valid": False, "reason": str(e)})
        report["recommendations"].append("Session invalid. Will auto-login on next MFA operation.")

    # VPN
    vpn_status = await vpn.status()
    report["checks"].append({"name": "VPN", "connected": vpn_status.connected, "tunnel_ip": vpn_status.local_ip})
    if not vpn_status.connected:
        cfg = vpn.find_config()
        report["recommendations"].append(
            f"VPN not connected. {'Config at ' + str(cfg) + '. ' if cfg else 'No config found. '}Use er_vpn_connect."
        )

    # SSH
    ssh_result = await ssh.test_connection()
    report["checks"].append({"name": "SSH", "success": ssh_result.success, "mfa_needed": ssh_result.mfa_needed})
    if ssh_result.mfa_needed:
        report["recommendations"].append("SSH failed (MFA). Run er_mfa_approve.")

    report["overall"] = "OK" if ssh_result.success else "ACTION_NEEDED"

    if not ssh_result.success and not vpn_status.connected:
        report["recommendations"].insert(0, "BEST FIX: er_vpn_connect (stable IP) → er_mfa_approve (once) → done.")

    return json.dumps(report, indent=2)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    mcp.run()


if __name__ == "__main__":
    main()
