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
import shlex
import time
from contextlib import asynccontextmanager
from functools import wraps
from typing import Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict

from kcl_er_mcp.auth import SessionManager, SessionError
from kcl_er_mcp.observability import (
    finish_call,
    get_health_snapshot,
    record_server_event,
    setup_observability,
    start_call,
)
from kcl_er_mcp.portal import PortalClient, get_current_ip
from kcl_er_mcp.vpn import VPNManager
from kcl_er_mcp.ssh_helper import SSHHelper

logging.basicConfig(
    level=os.environ.get("KCL_ER_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("kcl_er_mcp")
setup_observability()


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app):
    record_server_event("lifespan_start")
    sm = SessionManager()
    portal = PortalClient(sm)
    vpn = VPNManager()
    ssh = SSHHelper(portal=portal, session_manager=sm)
    try:
        yield {"sm": sm, "portal": portal, "vpn": vpn, "ssh": ssh}
    finally:
        record_server_event("lifespan_stop")
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
    command: str = Field(..., description="Short command to run on CREATE. Pass an explicit timeout for anything slow.", min_length=1, max_length=2000)
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


class SqueueInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    job_id: Optional[int] = Field(default=None, ge=1, description="Specific Slurm job ID to inspect")
    user: Optional[str] = Field(default=None, pattern=r"^[A-Za-z0-9._-]+$", description="User to query when job_id is omitted")
    timeout: int = Field(default=30, ge=5, le=120)


class SacctInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    job_id: int = Field(..., ge=1, description="Specific Slurm job ID to inspect")
    timeout: int = Field(default=30, ge=5, le=120)


class RemotePathInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    path: str = Field(..., min_length=1, max_length=500, pattern=r"^[^\r\n]+$", description="Remote path on CREATE")
    timeout: int = Field(default=30, ge=5, le=120)


class TailFileInput(RemotePathInput):
    lines: int = Field(default=80, ge=1, le=400)


class ListDirInput(RemotePathInput):
    max_entries: int = Field(default=120, ge=1, le=400)


class PrepareCreateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service: str = Field(default="ssh", pattern=r"^(ssh|openvpn)$")
    auto_approve_current_ip: bool = Field(default=True)
    ssh_probe: bool = Field(default=True)
    ssh_timeout: int = Field(default=20, ge=5, le=120)


# Helpers for safe tool execution
def _ctx_get(ctx, key):
    return ctx.request_context.lifespan_state.get(key) if ctx else None


def _tracked_call(kind: str, name: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            params = args[0] if args else kwargs.get("params")
            request_id, started_at = start_call(kind, name, params)
            try:
                result = await func(*args, **kwargs)
            except Exception as exc:
                finish_call(kind, name, request_id, started_at, status="error", error=str(exc))
                raise
            summary = {"response_bytes": len(result)} if isinstance(result, str) else {"response_type": type(result).__name__}
            finish_call(kind, name, request_id, started_at, status="ok", result=summary)
            return result

        return wrapper

    return decorator


def _json(data) -> str:
    return json.dumps(data, indent=2)


async def _safe(coro, error_prefix="") -> str:
    try:
        result = await coro
        return _json(result) if isinstance(result, (dict, list)) else str(result)
    except SessionError as e:
        return _json({"error": "session_error", "message": str(e)})
    except Exception as e:
        return _json({"error": error_prefix or "error", "message": str(e)})


async def _get_session_snapshot(portal: Optional[PortalClient] = None) -> dict:
    own_sm = None
    own_portal = portal is None
    if own_portal:
        own_sm = SessionManager()
        portal = PortalClient(own_sm)

    try:
        entries = await portal.get_mfa_entries()
        return {"valid": True, "entries_count": len(entries)}
    except SessionError as e:
        return {"valid": False, "reason": str(e)}
    except Exception as e:
        return {"valid": False, "reason": str(e)}
    finally:
        if own_portal:
            await portal.close()
            await own_sm.close()


async def _get_mfa_status_snapshot(portal: Optional[PortalClient] = None) -> dict:
    own_sm = None
    own_portal = portal is None
    if own_portal:
        own_sm = SessionManager()
        portal = PortalClient(own_sm)

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
        return {
            "current_ip": current_ip,
            "current_ip_status": ip_status,
            "entries": [e.to_dict() for e in entries],
            "counts": {"approved": len(approved), "pending": len(pending)},
        }
    except SessionError as e:
        return {"current_ip": current_ip, "error": "session_error", "message": str(e)}
    finally:
        if own_portal:
            await portal.close()
            await own_sm.close()


async def _get_diagnose_snapshot(ctx=None) -> dict:
    portal: PortalClient = _ctx_get(ctx, "portal")
    own_sm = None
    own_portal = portal is None
    if own_portal:
        own_sm = SessionManager()
        portal = PortalClient(own_sm)

    vpn: VPNManager = _ctx_get(ctx, "vpn") or VPNManager()
    ssh: SSHHelper = _ctx_get(ctx, "ssh") or SSHHelper()

    report = {"checks": [], "recommendations": []}
    ip = await get_current_ip()
    report["checks"].append({"name": "Public IP", "value": ip})

    try:
        entries = await portal.get_mfa_entries()
        report["checks"].append({"name": "Portal session", "valid": True})
        approved_ips = {e.ip_address for e in entries if e.status == "approved"}
        pending = [e for e in entries if e.status == "pending"]
        ip_ok = ip in approved_ips
        report["checks"].append({
            "name": "MFA",
            "current_ip_approved": ip_ok,
            "approved": len(approved_ips),
            "pending": len(pending),
        })
        if not ip_ok:
            report["recommendations"].append(f"IP {ip} not approved. Run er_mfa_approve.")
        if pending:
            report["recommendations"].append(f"{len(pending)} pending requests. Run er_mfa_approve_all.")
    except SessionError as e:
        report["checks"].append({"name": "Portal session", "valid": False, "reason": str(e)})
        report["recommendations"].append("Session invalid. Will auto-login on next MFA operation.")

    vpn_status = await vpn.status()
    vpn_check = {"name": "VPN", "connected": vpn_status.connected, "tunnel_ip": vpn_status.local_ip}
    cert_info = vpn.check_cert_expiry()
    if cert_info:
        vpn_check["cert_expiry"] = cert_info
        if cert_info.get("warning"):
            report["recommendations"].append(f"VPN certificate expires in {cert_info['days_remaining']} days. Download a new .ovpn from the portal.")
    report["checks"].append(vpn_check)
    if not vpn_status.connected:
        cfg = vpn.find_config()
        report["recommendations"].append(
            f"VPN not connected. {'Config at ' + str(cfg) + '. ' if cfg else 'No config found. '}Use er_vpn_connect."
        )

    ssh_result = await ssh.test_connection()
    ssh_check = {"name": "SSH", "success": ssh_result.success, "mfa_needed": ssh_result.mfa_needed}
    if ssh_result.timed_out:
        ssh_check["timed_out"] = True
    if ssh_result.error_type:
        ssh_check["error_type"] = ssh_result.error_type
    report["checks"].append(ssh_check)
    if ssh_result.mfa_needed:
        report["recommendations"].append("SSH failed (MFA). Run er_mfa_approve.")
    elif ssh_result.timed_out:
        report["recommendations"].append("SSH timed out. Use a larger timeout or a narrower read-only tool.")

    report["overall"] = "OK" if ssh_result.success else "ACTION_NEEDED"
    if not ssh_result.success and not vpn_status.connected:
        report["recommendations"].insert(0, "BEST FIX: er_vpn_connect (stable IP) → er_mfa_approve (once) → done.")

    if own_portal:
        await portal.close()
        await own_sm.close()

    return report


@asynccontextmanager
async def _portal_client(ctx=None):
    portal = _ctx_get(ctx, "portal")
    if portal is not None:
        yield portal
        return

    sm = SessionManager()
    portal = PortalClient(sm)
    try:
        yield portal
    finally:
        await portal.close()
        await sm.close()


async def _run_readonly_remote(ssh: SSHHelper, command: str, timeout: int) -> str:
    result = await ssh.run_command(command, timeout=timeout)
    payload = result.to_dict()
    if result.mfa_needed:
        payload["suggestion"] = "Run er_mfa_approve or er_vpn_connect first."
    elif result.timed_out:
        payload["suggestion"] = "Increase the timeout or use a narrower read-only monitoring tool."
    return _json(payload)


@mcp.resource("er://current-ip", title="Current IP", mime_type="application/json")
@_tracked_call("resource", "er://current-ip")
async def er_current_ip_resource() -> str:
    return _json({"ip": await get_current_ip()})


@mcp.resource("er://session", title="Portal Session", mime_type="application/json")
@_tracked_call("resource", "er://session")
async def er_session_resource() -> str:
    return _json(await _get_session_snapshot())


@mcp.resource("er://mfa-status", title="MFA Status", mime_type="application/json")
@_tracked_call("resource", "er://mfa-status")
async def er_mfa_status_resource() -> str:
    return _json(await _get_mfa_status_snapshot())


@mcp.resource("er://diagnose", title="Connectivity Diagnose", mime_type="application/json")
@_tracked_call("resource", "er://diagnose")
async def er_diagnose_resource() -> str:
    return _json(await _get_diagnose_snapshot())


@mcp.resource("er://health", title="Server Health", mime_type="application/json")
@_tracked_call("resource", "er://health")
async def er_health_resource() -> str:
    return _json(get_health_snapshot())


# ===========================================================================
# Auth Tools
# ===========================================================================

@mcp.tool(name="er_login", annotations={"title": "Login to Portal", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@_tracked_call("tool", "er_login")
async def er_login(params: EmptyInput, ctx=None) -> str:
    """Force SSO re-login to the e-Research portal.

    Normally login is automatic (triggered when session expires).
    Use this only if auto-login fails or you need to refresh credentials.

    Runs headless Playwright: email → password → TOTP → session saved.
    Credentials from env vars: KCL_EMAIL, KCL_PASSWORD, KCL_TOTP_SECRET.
    """
    sm: SessionManager = _ctx_get(ctx, "sm")
    if sm is not None:
        return await _safe(sm.login())

    sm = SessionManager()
    try:
        return await _safe(sm.login())
    finally:
        await sm.close()


@mcp.tool(name="er_session_check", annotations={"title": "Check Session", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@_tracked_call("tool", "er_session_check")
async def er_session_check(params: EmptyInput, ctx=None) -> str:
    """Check if portal session is valid. Tests by fetching /mfa page."""
    return _json(await _get_session_snapshot(_ctx_get(ctx, "portal")))


# ===========================================================================
# MFA Tools
# ===========================================================================

@mcp.tool(name="er_mfa_status", annotations={"title": "MFA Status", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@_tracked_call("tool", "er_mfa_status")
async def er_mfa_status(params: EmptyInput, ctx=None) -> str:
    """List all MFA entries (approved + pending) and check current IP status.

    Auto-logs in if session expired. Returns entries with service, IP,
    location, expiry, status. Highlights whether your current IP is approved.
    """
    return _json(await _get_mfa_status_snapshot(_ctx_get(ctx, "portal")))


@mcp.tool(name="er_mfa_approve", annotations={"title": "Approve IP", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@_tracked_call("tool", "er_mfa_approve")
async def er_mfa_approve(params: ApproveInput, ctx=None) -> str:
    """Approve an IP for SSH/VPN access to CREATE.

    If ip_address omitted, auto-detects current public IP.
    Calls POST /api/internal/mfa/approve. Idempotent.
    Auto-logs in if session expired.
    """
    async with _portal_client(ctx) as portal:
        if params.ip_address:
            return await _safe(portal.approve_ip(params.ip_address, params.service))
        return await _safe(portal.approve_current_ip(params.service))


@mcp.tool(name="er_mfa_approve_all", annotations={"title": "Approve All Pending", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@_tracked_call("tool", "er_mfa_approve_all")
async def er_mfa_approve_all(params: EmptyInput, ctx=None) -> str:
    """Approve ALL pending MFA requests in one shot.

    Fetches pending list, then approves each one via API.
    Perfect for when mobile hotspot triggered multiple MFA requests.
    """
    async with _portal_client(ctx) as portal:
        return await _safe(portal.approve_all_pending())


@mcp.tool(name="er_mfa_revoke", annotations={"title": "Revoke IP", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True})
@_tracked_call("tool", "er_mfa_revoke")
async def er_mfa_revoke(params: RevokeInput, ctx=None) -> str:
    """Revoke an approved/pending IP from MFA."""
    async with _portal_client(ctx) as portal:
        return await _safe(portal.reject_ip(params.ip_address, params.service))


# ===========================================================================
# VPN Tools
# ===========================================================================

@mcp.tool(name="er_vpn_status", annotations={"title": "VPN Status", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
@_tracked_call("tool", "er_vpn_status")
async def er_vpn_status(params: EmptyInput, ctx=None) -> str:
    """Check OpenVPN connection to bastion.er.kcl.ac.uk."""
    vpn: VPNManager = _ctx_get(ctx, "vpn") or VPNManager()
    status = await vpn.status()
    r = status.to_dict()
    r["public_ip"] = await get_current_ip()
    cfg = vpn.find_config()
    r["config_found"] = str(cfg) if cfg else None
    cert_info = vpn.check_cert_expiry(cfg)
    if cert_info:
        r["cert_expiry"] = cert_info
        if cert_info.get("warning"):
            r["warning"] = f"VPN certificate expires in {cert_info['days_remaining']} days!"
    return json.dumps(r, indent=2)


@mcp.tool(name="er_vpn_connect", annotations={"title": "Connect VPN", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@_tracked_call("tool", "er_vpn_connect")
async def er_vpn_connect(params: VPNConfigInput, ctx=None) -> str:
    """Start OpenVPN tunnel. Requires openvpn + sudo."""
    vpn: VPNManager = _ctx_get(ctx, "vpn") or VPNManager()
    status = await vpn.connect(params.config_path)
    return json.dumps(status.to_dict(), indent=2)


@mcp.tool(name="er_vpn_disconnect", annotations={"title": "Disconnect VPN", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
@_tracked_call("tool", "er_vpn_disconnect")
async def er_vpn_disconnect(params: EmptyInput, ctx=None) -> str:
    """Stop OpenVPN tunnel."""
    vpn: VPNManager = _ctx_get(ctx, "vpn") or VPNManager()
    status = await vpn.disconnect()
    return json.dumps(status.to_dict(), indent=2)


@mcp.tool(name="er_vpn_log", annotations={"title": "VPN Log", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
@_tracked_call("tool", "er_vpn_log")
async def er_vpn_log(params: EmptyInput, ctx=None) -> str:
    """Last 50 lines of OpenVPN log."""
    vpn: VPNManager = _ctx_get(ctx, "vpn") or VPNManager()
    return vpn.get_log_tail(50)


# ===========================================================================
# SSH Tools
# ===========================================================================

@mcp.tool(name="er_ssh_test", annotations={"title": "Test SSH", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@_tracked_call("tool", "er_ssh_test")
async def er_ssh_test(params: EmptyInput, ctx=None) -> str:
    """Test SSH to CREATE. Diagnoses MFA issues if connection fails."""
    ssh: SSHHelper = _ctx_get(ctx, "ssh") or SSHHelper()
    r = await ssh.test_connection()
    d = r.to_dict()
    if r.mfa_needed:
        d["suggestion"] = "MFA needed. Run er_mfa_approve or er_vpn_connect."
    elif r.timed_out:
        d["suggestion"] = "SSH timed out. Use a larger timeout or one of the narrow read-only monitoring tools."
    return json.dumps(d, indent=2)


@mcp.tool(name="er_ssh_run", annotations={"title": "Run on CREATE", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@_tracked_call("tool", "er_ssh_run")
async def er_ssh_run(params: SSHCommandInput, ctx=None) -> str:
    """Execute a command on CREATE HPC via SSH. PREFER using direct `ssh create '<command>'`
    after running er_prepare_create — it is faster and does not require tool approval.
    Use this tool only as a fallback when direct SSH is unavailable."""
    ssh: SSHHelper = _ctx_get(ctx, "ssh") or SSHHelper()
    r = await ssh.run_command(params.command, timeout=params.timeout)
    d = r.to_dict()
    if r.mfa_needed:
        d["suggestion"] = "Run er_mfa_approve or er_vpn_connect first."
    elif r.timed_out:
        d["suggestion"] = "Avoid long polling here. Use an explicit timeout or a narrower read-only monitoring tool."
    return json.dumps(d, indent=2)


@mcp.tool(name="er_scp_transfer", annotations={"title": "SCP Transfer", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
@_tracked_call("tool", "er_scp_transfer")
async def er_scp_transfer(params: SCPInput, ctx=None) -> str:
    """Transfer files. PREFER `scp create:<remote> <local>` after er_prepare_create."""
    ssh: SSHHelper = _ctx_get(ctx, "ssh") or SSHHelper()
    if params.direction == "download":
        r = await ssh.scp_download(params.remote_path, params.local_path, params.timeout)
    else:
        r = await ssh.scp_upload(params.local_path, params.remote_path, params.timeout)
    return json.dumps(r.to_dict(), indent=2)


@mcp.tool(name="er_ssh_setup", annotations={"title": "Setup SSH", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
@_tracked_call("tool", "er_ssh_setup")
async def er_ssh_setup(params: EmptyInput, ctx=None) -> str:
    """Add ControlMaster config to ~/.ssh/config for CREATE."""
    ssh: SSHHelper = _ctx_get(ctx, "ssh") or SSHHelper()
    result = ssh.ensure_ssh_config()
    cm = await ssh.check_control_master()
    return json.dumps({"config_result": result, "control_master": cm}, indent=2)


@mcp.tool(name="er_squeue", annotations={"title": "Read squeue", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@_tracked_call("tool", "er_squeue")
async def er_squeue(params: SqueueInput, ctx=None) -> str:
    """Read Slurm queue state. PREFER `ssh create 'squeue -u <user>'` after er_prepare_create."""
    ssh: SSHHelper = _ctx_get(ctx, "ssh") or SSHHelper()
    if params.job_id is not None:
        command = f"squeue -j {params.job_id} -o '%i %T %M %R'"
    else:
        user = params.user or ssh.user
        command = f"squeue -u {shlex.quote(user)} -o '%i %T %M %R'"
    return await _run_readonly_remote(ssh, command, params.timeout)


@mcp.tool(name="er_sacct", annotations={"title": "Read sacct", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@_tracked_call("tool", "er_sacct")
async def er_sacct(params: SacctInput, ctx=None) -> str:
    """Read Slurm accounting for one job. PREFER `ssh create 'sacct -j <id> ...'` after er_prepare_create."""
    ssh: SSHHelper = _ctx_get(ctx, "ssh") or SSHHelper()
    command = f"sacct -j {params.job_id} --format=JobID,State,ExitCode,Elapsed -n -P"
    return await _run_readonly_remote(ssh, command, params.timeout)


@mcp.tool(name="er_tail_file", annotations={"title": "Tail Remote File", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@_tracked_call("tool", "er_tail_file")
async def er_tail_file(params: TailFileInput, ctx=None) -> str:
    """Tail a remote file. PREFER `ssh create 'tail -n 80 <path>'` after er_prepare_create."""
    ssh: SSHHelper = _ctx_get(ctx, "ssh") or SSHHelper()
    command = f"tail -n {params.lines} {shlex.quote(params.path)} 2>/dev/null || true"
    return await _run_readonly_remote(ssh, command, params.timeout)


@mcp.tool(name="er_ls", annotations={"title": "List Remote Directory", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@_tracked_call("tool", "er_ls")
async def er_ls(params: ListDirInput, ctx=None) -> str:
    """List a remote directory. PREFER `ssh create 'ls -lah <path>'` after er_prepare_create."""
    ssh: SSHHelper = _ctx_get(ctx, "ssh") or SSHHelper()
    command = f"(ls -lah {shlex.quote(params.path)} 2>/dev/null || true) | tail -n {params.max_entries}"
    return await _run_readonly_remote(ssh, command, params.timeout)


@mcp.tool(name="er_prepare_create", annotations={"title": "Prepare CREATE Access", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@_tracked_call("tool", "er_prepare_create")
async def er_prepare_create(params: PrepareCreateInput, ctx=None) -> str:
    """Prepare CREATE access in one idempotent call: SSH config, session, current IP approval, and SSH probe.

    After this succeeds, the agent SHOULD use direct `ssh create <command>` for all
    subsequent commands — do NOT use er_ssh_run for routine work.
    """
    ssh: SSHHelper = _ctx_get(ctx, "ssh") or SSHHelper()
    report = {
        "actions": [],
        "ssh_config": None,
        "session": None,
        "mfa": None,
        "ssh": None,
        "hint": "After success, run commands directly via: ssh create '<command>'",
        "duration_ms": None,
    }
    started = time.perf_counter()

    # Ensure ~/.ssh/config has the Host create alias with ControlMaster
    config_result = ssh.ensure_ssh_config()
    report["ssh_config"] = config_result
    report["actions"].append({"action": "ensure_ssh_config", "result": config_result})

    async with _portal_client(ctx) as portal:
        report["session"] = await _get_session_snapshot(portal)
        report["mfa"] = await _get_mfa_status_snapshot(portal)

        if params.auto_approve_current_ip and report["mfa"].get("current_ip_status") != "APPROVED":
            approval = await portal.approve_current_ip(params.service)
            report["actions"].append(
                {
                    "action": "approve_current_ip",
                    "service": params.service,
                    "result": approval,
                }
            )
            report["mfa"] = await _get_mfa_status_snapshot(portal)

    if params.ssh_probe:
        ssh_result = await ssh.run_command("echo CONNECTION_OK && hostname", timeout=params.ssh_timeout)
        report["ssh"] = ssh_result.to_dict()
        if ssh_result.mfa_needed:
            report["actions"].append(
                {
                    "action": "follow_up",
                    "message": "SSH still reports MFA. Re-run er_prepare_create after IP propagation or connect VPN first.",
                }
            )
        elif ssh_result.timed_out:
            report["actions"].append(
                {
                    "action": "follow_up",
                    "message": "SSH probe timed out. Increase ssh_timeout or run er_ssh_test once connectivity stabilizes.",
                }
            )

    report["control_master"] = await ssh.get_control_master_info()
    report["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return _json(report)


# ===========================================================================
# Utility
# ===========================================================================

@mcp.tool(name="er_current_ip", annotations={"title": "Current IP", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@_tracked_call("tool", "er_current_ip")
async def er_current_ip(params: EmptyInput) -> str:
    """Get current public IP."""
    return _json({"ip": await get_current_ip()})


@mcp.tool(name="er_diagnose", annotations={"title": "Diagnose", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
@_tracked_call("tool", "er_diagnose")
async def er_diagnose(params: EmptyInput, ctx=None) -> str:
    """Full connectivity diagnostic: IP → session → VPN → SSH → MFA.

    Returns structured report with specific fix recommendations.
    """
    return _json(await _get_diagnose_snapshot(ctx))


@mcp.tool(name="er_health", annotations={"title": "Server Health", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
@_tracked_call("tool", "er_health")
async def er_health(params: EmptyInput) -> str:
    """Inspect server uptime, local logs, and timeout/error counters."""
    return _json(get_health_snapshot())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    mcp.run()


if __name__ == "__main__":
    main()
