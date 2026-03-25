"""OpenVPN connection management for KCL e-Research bastion."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

STATE_DIR = Path.home() / ".kcl-er-mcp"
VPN_LOG_FILE = STATE_DIR / "openvpn.log"
DEFAULT_OVPN_DIR = STATE_DIR / "vpn-configs"


@dataclass
class VPNStatus:
    connected: bool
    pid: Optional[int] = None
    config_file: Optional[str] = None
    local_ip: Optional[str] = None
    remote_ip: Optional[str] = None
    connected_since: Optional[datetime] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "connected": self.connected, "pid": self.pid,
            "config_file": self.config_file, "local_ip": self.local_ip,
            "remote_ip": self.remote_ip,
            "connected_since": self.connected_since.isoformat() if self.connected_since else None,
            "error": self.error,
        }


class VPNManager:
    def __init__(self, ovpn_config: Optional[str] = None) -> None:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        DEFAULT_OVPN_DIR.mkdir(parents=True, exist_ok=True)
        self._config_path = ovpn_config

    def find_config(self) -> Optional[Path]:
        if self._config_path:
            p = Path(self._config_path)
            if p.exists():
                self._secure_config(p)
                return p
        env = os.environ.get("KCL_ER_OVPN_CONFIG")
        if env:
            p = Path(env)
            if p.exists():
                self._secure_config(p)
                return p
        for ovpn in DEFAULT_OVPN_DIR.glob("*.ovpn"):
            self._secure_config(ovpn)
            return ovpn
        dl = Path.home() / "Downloads"
        if dl.exists():
            for ovpn in sorted(dl.glob("*kcl*.ovpn"), reverse=True):
                self._secure_config(ovpn)
                return ovpn
        return None

    @staticmethod
    def _secure_config(path: Path) -> None:
        """Ensure .ovpn file is chmod 600 (contains private keys)."""
        try:
            current = path.stat().st_mode & 0o777
            if current != 0o600:
                path.chmod(0o600)
                logger.info("Fixed .ovpn permissions: %s (%o -> 600)", path, current)
        except OSError:
            pass

    def check_cert_expiry(self, config_path: Optional[Path] = None) -> Optional[dict]:
        """Parse embedded certificate in .ovpn and check expiry date."""
        cfg = config_path or self.find_config()
        if not cfg or not cfg.exists():
            return None
        try:
            content = cfg.read_text()
        except OSError:
            return None
        # Extract PEM block between <cert> and </cert>
        m = re.search(r"<cert>\s*(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)", content, re.DOTALL)
        if not m:
            return None
        try:
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(m.group(1).encode())
            expires = cert.not_valid_after_utc
            days_remaining = (expires - datetime.now(timezone.utc)).days
            return {
                "expires_at": expires.isoformat(),
                "days_remaining": days_remaining,
                "warning": days_remaining <= 14,
            }
        except Exception:
            return None

    async def connect(self, config_path: Optional[str] = None) -> VPNStatus:
        status = await self.status()
        if status.connected:
            return status
        cfg = Path(config_path) if config_path else self.find_config()
        if not cfg or not cfg.exists():
            return VPNStatus(connected=False, error="No .ovpn config found.")
        self._secure_config(cfg)
        openvpn = self._find_openvpn()
        if not openvpn:
            return VPNStatus(connected=False, error="openvpn not found. Install: brew install openvpn")
        try:
            # Pre-create log file with user ownership so we can read it later
            VPN_LOG_FILE.touch(exist_ok=True)
            proc = await asyncio.create_subprocess_exec(
                "sudo", openvpn, "--config", str(cfg),
                "--log-append", str(VPN_LOG_FILE),
                "--daemon", "kcl-er-vpn",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            for i in range(60):
                await asyncio.sleep(1)
                # Fix log permissions once it exists
                if i == 3 and VPN_LOG_FILE.exists():
                    fix = await asyncio.create_subprocess_exec(
                        "sudo", "chmod", "644", str(VPN_LOG_FILE),
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    )
                    await fix.communicate()
                s = await self.status()
                if s.connected:
                    return s
            return VPNStatus(connected=False, config_file=str(cfg), error="Connection timeout")
        except Exception as e:
            return VPNStatus(connected=False, error=str(e))

    async def disconnect(self) -> VPNStatus:
        pid = await self._find_pid()
        if pid:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "sudo", "kill", str(pid),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()
                for _ in range(10):
                    if not await self._find_pid():
                        break
                    await asyncio.sleep(0.5)
            except Exception:
                pass
        return VPNStatus(connected=False)

    async def status(self) -> VPNStatus:
        pid = await self._find_pid()
        if not pid:
            return VPNStatus(connected=False)
        # Check if "Initialization Sequence Completed" in log
        log = await self._read_log()
        if not log or "Initialization Sequence Completed" not in log:
            return VPNStatus(connected=False, pid=pid)
        local_ip = None
        m = re.search(r"/sbin/ifconfig\s+utun\d+\s+(\d+\.\d+\.\d+\.\d+)", log)
        if m:
            local_ip = m.group(1)
        return VPNStatus(connected=True, pid=pid, local_ip=local_ip, remote_ip="bastion.er.kcl.ac.uk")

    async def _read_log(self) -> Optional[str]:
        """Read VPN log file, using sudo if needed."""
        if not VPN_LOG_FILE.exists():
            return None
        try:
            return VPN_LOG_FILE.read_text()
        except PermissionError:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "sudo", "cat", str(VPN_LOG_FILE),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                return stdout.decode(errors="replace")
            except Exception:
                return None

    async def _find_pid(self) -> Optional[int]:
        """Find openvpn PID via pgrep (works regardless of file permissions)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "pgrep", "-f", "openvpn.*kcl-er-vpn",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0 and stdout.strip():
                return int(stdout.strip().split()[0])
        except Exception:
            pass
        return None

    def get_log_tail(self, lines: int = 50) -> str:
        if not VPN_LOG_FILE.exists():
            return "No VPN log file."
        try:
            all_lines = VPN_LOG_FILE.read_text().splitlines()
        except PermissionError:
            try:
                r = subprocess.run(
                    ["sudo", "tail", f"-{lines}", str(VPN_LOG_FILE)],
                    capture_output=True, timeout=5,
                )
                return r.stdout.decode(errors="replace")
            except Exception:
                return "Permission denied reading VPN log."
        return "\n".join(all_lines[-lines:])

    @staticmethod
    def _find_openvpn() -> Optional[str]:
        for c in ["/opt/homebrew/sbin/openvpn", "/usr/local/sbin/openvpn", "/usr/sbin/openvpn", "openvpn"]:
            try:
                r = subprocess.run([c, "--version"], capture_output=True, timeout=5)
                if r.returncode in (0, 1):
                    return c
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return None
