"""SSH connection helper with MFA-aware retry for CREATE HPC."""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

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
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "stdout": self.stdout[:2000] if self.stdout else "",
            "stderr": self.stderr[:500] if self.stderr else "",
            "return_code": self.return_code,
            "mfa_needed": self.mfa_needed,
            "error": self.error,
        }


class SSHHelper:
    def __init__(self, k_number: Optional[str] = None) -> None:
        self._k_number = k_number or os.environ.get("KCL_K_NUMBER") or os.environ.get("KCL_EMAIL", "").split("@")[0]
        SSH_SOCKETS_DIR.mkdir(parents=True, exist_ok=True)

    @property
    def user(self) -> str:
        if not self._k_number:
            raise ValueError("K-number not set. Set KCL_K_NUMBER or KCL_EMAIL env var.")
        return self._k_number

    def ensure_ssh_config(self) -> str:
        ssh_config = Path.home() / ".ssh" / "config"
        ssh_config.parent.mkdir(mode=0o700, exist_ok=True)
        block = f"""
# KCL CREATE HPC — managed by kcl-er-mcp
Host create
    HostName {CREATE_HOST}
    User {self.user}
    ControlMaster auto
    ControlPath {SSH_SOCKETS_DIR}/%r@%h-%p
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
        socket = SSH_SOCKETS_DIR / f"{self.user}@{CREATE_HOST}-22"
        if not socket.exists():
            return {"active": False, "socket": str(socket)}
        proc = await asyncio.create_subprocess_exec(
            "ssh", "-O", "check", "create",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        return {"active": proc.returncode == 0, "socket": str(socket), "message": stderr.decode().strip()}

    async def run_command(self, command: str, timeout: int = 60) -> SSHResult:
        args = [
            "ssh", "-o", "ConnectTimeout=15", "-o", "BatchMode=yes",
            "-o", f"ControlPath={SSH_SOCKETS_DIR}/%r@%h-%p",
            f"{self.user}@{CREATE_HOST}", command,
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            so, se = stdout.decode(errors="replace"), stderr.decode(errors="replace")
            if proc.returncode == 0:
                return SSHResult(success=True, stdout=so, stderr=se, return_code=0)
            mfa = any(re.search(p, se, re.I) for p in MFA_ERROR_PATTERNS)
            return SSHResult(success=False, stdout=so, stderr=se, return_code=proc.returncode or -1, mfa_needed=mfa, error=f"SSH failed: {se[:200]}")
        except asyncio.TimeoutError:
            return SSHResult(success=False, mfa_needed=True, error=f"Timeout after {timeout}s")
        except Exception as e:
            return SSHResult(success=False, error=str(e))

    async def scp_download(self, remote: str, local: str, timeout: int = 300) -> SSHResult:
        return await self._scp([f"{self.user}@{CREATE_HOST}:{remote}", local], timeout)

    async def scp_upload(self, local: str, remote: str, timeout: int = 300) -> SSHResult:
        return await self._scp([local, f"{self.user}@{CREATE_HOST}:{remote}"], timeout)

    async def _scp(self, paths: list[str], timeout: int) -> SSHResult:
        args = ["scp", "-o", "ConnectTimeout=15", "-o", f"ControlPath={SSH_SOCKETS_DIR}/%r@%h-%p"] + paths
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            so, se = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return SSHResult(success=proc.returncode == 0, stdout=so.decode(errors="replace"), stderr=se.decode(errors="replace"), return_code=proc.returncode or -1)
        except asyncio.TimeoutError:
            return SSHResult(success=False, error=f"SCP timeout after {timeout}s")
