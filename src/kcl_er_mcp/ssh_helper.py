"""SSH connection helper with MFA-aware retry for CREATE HPC."""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from kcl_er_mcp.observability import record_remote_exec

logger = logging.getLogger(__name__)

CREATE_HOST = "hpc.create.kcl.ac.uk"
SSH_SOCKETS_DIR = Path.home() / ".ssh" / "sockets"

MFA_ERROR_PATTERNS = [
    r"Permission denied", r"Connection refused", r"Connection reset",
    r"Connection timed out", r"Network is unreachable", r"No route to host",
]


@dataclass
class SSHResult:
    success: bool
    stdout: str = ""
    stderr: str = ""
    return_code: int = -1
    mfa_needed: bool = False
    timed_out: bool = False
    auto_recovered: bool = False
    error_type: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        d = {
            "success": self.success,
            "stdout": self.stdout[:2000] if self.stdout else "",
            "stderr": self.stderr[:500] if self.stderr else "",
            "return_code": self.return_code,
            "mfa_needed": self.mfa_needed,
            "timed_out": self.timed_out,
            "error_type": self.error_type,
            "error": self.error,
        }
        if self.auto_recovered:
            d["auto_recovered"] = True
        return d


class SSHHelper:
    def __init__(self, k_number: Optional[str] = None, portal=None, session_manager=None) -> None:
        self._k_number = k_number or os.environ.get("KCL_K_NUMBER") or os.environ.get("KCL_EMAIL", "").split("@")[0]
        self._portal = portal  # Optional PortalClient for auto-recovery
        self._sm = session_manager
        SSH_SOCKETS_DIR.mkdir(parents=True, exist_ok=True)

    async def _try_mfa_recovery(self) -> bool:
        """Attempt to auto-approve current IP when SSH fails with MFA error. Returns True on success."""
        if self._portal is None:
            return False
        try:
            logger.info("SSH MFA failure detected, attempting auto-recovery...")
            result = await self._portal.approve_current_ip("ssh")
            ok = result.get("success", False)
            logger.info("MFA auto-recovery %s", "succeeded" if ok else "failed")
            return ok
        except Exception as e:
            logger.warning("MFA auto-recovery error: %s", e)
            return False

    @property
    def user(self) -> str:
        if not self._k_number:
            raise ValueError("K-number not set. Set KCL_K_NUMBER or KCL_EMAIL env var.")
        return self._k_number

    def ensure_ssh_config(self) -> str:
        ssh_config = Path.home() / ".ssh" / "config"
        ssh_config.parent.mkdir(mode=0o700, exist_ok=True)
        socket_path = self._control_socket()
        block = f"""
# KCL CREATE HPC — managed by kcl-er-mcp
Host create {CREATE_HOST}
    HostName {CREATE_HOST}
    User {self.user}
    ControlMaster auto
    ControlPath {socket_path}
    ControlPersist 4h
    ServerAliveInterval 60
    ServerAliveCountMax 3
    StrictHostKeyChecking accept-new
"""
        if ssh_config.exists():
            existing = ssh_config.read_text()
            if "kcl-er-mcp" in existing:
                return "SSH config already contains CREATE settings."
            if CREATE_HOST in existing:
                return f"Existing entry for {CREATE_HOST} found. Add ControlMaster manually."
            with ssh_config.open("a") as f:
                f.write(block)
            ssh_config.chmod(0o600)
            return f"Appended CREATE config to {ssh_config}"
        ssh_config.write_text(block)
        ssh_config.chmod(0o600)
        return f"Created {ssh_config} with CREATE config"

    async def test_connection(self) -> SSHResult:
        return await self.run_command("echo CONNECTION_OK && hostname")

    async def check_control_master(self) -> dict:
        socket = self._control_socket()
        if not socket.exists():
            return {"active": False, "socket": str(socket)}
        proc = await asyncio.create_subprocess_exec(
            "ssh", "-S", str(socket), "-O", "check", f"{self.user}@{CREATE_HOST}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        return {"active": proc.returncode == 0, "socket": str(socket), "message": stderr.decode().strip()}

    async def get_control_master_info(self) -> dict:
        """Get ControlMaster socket info including remaining TTL."""
        cm = await self.check_control_master()
        socket = self._control_socket()
        if not cm.get("active") or not socket.exists():
            return cm
        try:
            mtime = socket.stat().st_mtime
            created = datetime.fromtimestamp(mtime, tz=timezone.utc)
            elapsed = (datetime.now(timezone.utc) - created).total_seconds()
            ttl = max(0, 14400 - int(elapsed))  # ControlPersist 4h = 14400s
            hours, remainder = divmod(ttl, 3600)
            minutes = remainder // 60
            cm["created_at"] = created.isoformat()
            cm["ttl_remaining_seconds"] = ttl
            cm["ttl_remaining_human"] = f"{hours}h {minutes}m"
        except OSError:
            pass
        return cm

    def _control_socket(self) -> Path:
        return SSH_SOCKETS_DIR / f"{self.user}@{CREATE_HOST}-22"

    def _ssh_args(self) -> list[str]:
        return [
            "ssh",
            "-o", "ConnectTimeout=15",
            "-o", "BatchMode=yes",
            "-o", "ControlMaster=auto",
            "-o", "ControlPersist=4h",
            "-o", "ServerAliveInterval=60",
            "-o", "ServerAliveCountMax=3",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"ControlPath={self._control_socket()}",
        ]

    async def _cleanup_subprocess(self, proc: asyncio.subprocess.Process) -> tuple[bytes, bytes]:
        if proc.returncode is not None:
            return await proc.communicate()

        try:
            proc.terminate()
        except ProcessLookupError:
            return await proc.communicate()

        try:
            return await asyncio.wait_for(proc.communicate(), timeout=5)
        except asyncio.TimeoutError:
            logger.warning("Timed out waiting for subprocess %s to terminate; killing it", proc.pid)
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return await proc.communicate()

    async def _exec_ssh(self, command: str, timeout: int = 60) -> SSHResult:
        """Low-level SSH exec — no auto-recovery, no observability recording."""
        args = [*self._ssh_args(), f"{self.user}@{CREATE_HOST}", command]
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            so, se = stdout.decode(errors="replace"), stderr.decode(errors="replace")
            if proc.returncode == 0:
                return SSHResult(success=True, stdout=so, stderr=se, return_code=0)
            mfa = any(re.search(p, se, re.I) for p in MFA_ERROR_PATTERNS)
            return SSHResult(
                success=False, stdout=so, stderr=se,
                return_code=proc.returncode or -1,
                mfa_needed=mfa, error_type="mfa" if mfa else "ssh",
                error=f"SSH failed: {se[:200]}",
            )
        except asyncio.TimeoutError:
            return SSHResult(success=False, timed_out=True, error_type="timeout", error=f"Timeout after {timeout}s")
        except Exception as e:
            return SSHResult(success=False, error_type="exception", error=str(e))

    async def run_command(self, command: str, timeout: int = 60) -> SSHResult:
        args = [*self._ssh_args(), f"{self.user}@{CREATE_HOST}", command]
        proc: Optional[asyncio.subprocess.Process] = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            so, se = stdout.decode(errors="replace"), stderr.decode(errors="replace")
            if proc.returncode == 0:
                record_remote_exec(
                    "ssh",
                    command=command,
                    timeout=timeout,
                    pid=proc.pid,
                    return_code=0,
                    timed_out=False,
                    error_type=None,
                    stderr=se,
                )
                return SSHResult(success=True, stdout=so, stderr=se, return_code=0)
            mfa = any(re.search(p, se, re.I) for p in MFA_ERROR_PATTERNS)
            error_type = "mfa" if mfa else "ssh"
            record_remote_exec(
                "ssh",
                command=command,
                timeout=timeout,
                pid=proc.pid,
                return_code=proc.returncode,
                timed_out=False,
                error_type=error_type,
                stderr=se,
            )
            # Auto-recovery: approve current IP and retry once
            if mfa and await self._try_mfa_recovery():
                await asyncio.sleep(2)  # Wait for MFA propagation
                retry = await self._exec_ssh(command, timeout)
                retry.auto_recovered = retry.success
                record_remote_exec(
                    "ssh",
                    command=command,
                    timeout=timeout,
                    pid=None,
                    return_code=retry.return_code,
                    timed_out=retry.timed_out,
                    error_type=None if retry.success else "ssh_retry",
                    stderr=retry.stderr[:200],
                )
                return retry
            return SSHResult(
                success=False,
                stdout=so,
                stderr=se,
                return_code=proc.returncode or -1,
                mfa_needed=mfa,
                error_type=error_type,
                error=f"SSH failed: {se[:200]}",
            )
        except asyncio.TimeoutError:
            if proc is None:
                record_remote_exec(
                    "ssh",
                    command=command,
                    timeout=timeout,
                    pid=None,
                    return_code=None,
                    timed_out=True,
                    error_type="timeout",
                )
                return SSHResult(success=False, timed_out=True, error_type="timeout", error=f"Timeout after {timeout}s")
            stdout, stderr = await self._cleanup_subprocess(proc)
            so, se = stdout.decode(errors="replace"), stderr.decode(errors="replace")
            logger.warning("SSH command timed out after %ss (pid=%s)", timeout, proc.pid)
            record_remote_exec(
                "ssh",
                command=command,
                timeout=timeout,
                pid=proc.pid,
                return_code=proc.returncode,
                timed_out=True,
                error_type="timeout",
                stderr=se,
            )
            return SSHResult(
                success=False,
                stdout=so,
                stderr=se,
                return_code=proc.returncode or -1,
                timed_out=True,
                error_type="timeout",
                error=f"Timeout after {timeout}s",
            )
        except Exception as e:
            record_remote_exec(
                "ssh",
                command=command,
                timeout=timeout,
                pid=getattr(proc, "pid", None),
                return_code=getattr(proc, "returncode", None),
                timed_out=False,
                error_type="exception",
                stderr=str(e),
            )
            return SSHResult(success=False, error_type="exception", error=str(e))

    async def scp_download(self, remote: str, local: str, timeout: int = 300) -> SSHResult:
        return await self._scp([f"{self.user}@{CREATE_HOST}:{remote}", local], timeout)

    async def scp_upload(self, local: str, remote: str, timeout: int = 300) -> SSHResult:
        return await self._scp([local, f"{self.user}@{CREATE_HOST}:{remote}"], timeout)

    async def _scp(self, paths: list[str], timeout: int) -> SSHResult:
        transfer_desc = " -> ".join(paths)
        args = [
            "scp",
            "-o", "ConnectTimeout=15",
            "-o", "ControlMaster=auto",
            "-o", "ControlPersist=4h",
            "-o", "ServerAliveInterval=60",
            "-o", "ServerAliveCountMax=3",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"ControlPath={self._control_socket()}",
        ] + paths
        proc: Optional[asyncio.subprocess.Process] = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            so, se = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            record_remote_exec(
                "scp",
                command=transfer_desc,
                timeout=timeout,
                pid=proc.pid,
                return_code=proc.returncode,
                timed_out=False,
                error_type=None if proc.returncode == 0 else "scp",
                stderr=se.decode(errors="replace"),
            )
            return SSHResult(
                success=proc.returncode == 0,
                stdout=so.decode(errors="replace"),
                stderr=se.decode(errors="replace"),
                return_code=proc.returncode or -1,
                error_type=None if proc.returncode == 0 else "scp",
                error=None if proc.returncode == 0 else f"SCP failed: {se.decode(errors='replace')[:200]}",
            )
        except asyncio.TimeoutError:
            if proc is None:
                record_remote_exec(
                    "scp",
                    command=transfer_desc,
                    timeout=timeout,
                    pid=None,
                    return_code=None,
                    timed_out=True,
                    error_type="timeout",
                )
                return SSHResult(success=False, timed_out=True, error_type="timeout", error=f"SCP timeout after {timeout}s")
            so, se = await self._cleanup_subprocess(proc)
            logger.warning("SCP transfer timed out after %ss (pid=%s)", timeout, proc.pid)
            record_remote_exec(
                "scp",
                command=transfer_desc,
                timeout=timeout,
                pid=proc.pid,
                return_code=proc.returncode,
                timed_out=True,
                error_type="timeout",
                stderr=se.decode(errors="replace"),
            )
            return SSHResult(
                success=False,
                stdout=so.decode(errors="replace"),
                stderr=se.decode(errors="replace"),
                return_code=proc.returncode or -1,
                timed_out=True,
                error_type="timeout",
                error=f"SCP timeout after {timeout}s",
            )
        except Exception as e:
            record_remote_exec(
                "scp",
                command=transfer_desc,
                timeout=timeout,
                pid=getattr(proc, "pid", None),
                return_code=getattr(proc, "returncode", None),
                timed_out=False,
                error_type="exception",
                stderr=str(e),
            )
            return SSHResult(success=False, error_type="exception", error=str(e))
