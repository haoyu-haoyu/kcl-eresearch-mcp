"""OpenVPN connection management for KCL e-Research bastion."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import signal
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

STATE_DIR = Path.home() / ".kcl-er-mcp"
VPN_PID_FILE = STATE_DIR / "openvpn.pid"
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
                return p
        env = os.environ.get("KCL_ER_OVPN_CONFIG")
        if env:
            p = Path(env)
            if p.exists():
                return p
        for ovpn in DEFAULT_OVPN_DIR.glob("*.ovpn"):
            return ovpn
        dl = Path.home() / "Downloads"
        if dl.exists():
            for ovpn in sorted(dl.glob("*kcl*.ovpn"), reverse=True):
                return ovpn
        return None

    async def connect(self, config_path: Optional[str] = None) -> VPNStatus:
        status = await self.status()
        if status.connected:
            return status
        cfg = Path(config_path) if config_path else self.find_config()
        if not cfg or not cfg.exists():
            return VPNStatus(connected=False, error="No .ovpn config found.")
        openvpn = self._find_openvpn()
        if not openvpn:
            return VPNStatus(connected=False, error="openvpn not found. Install: brew install openvpn")
        try:
            proc = await asyncio.create_subprocess_exec(
                "sudo", openvpn, "--config", str(cfg),
                "--log", str(VPN_LOG_FILE), "--writepid", str(VPN_PID_FILE),
                "--daemon", "kcl-er-vpn",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            for _ in range(30):
                await asyncio.sleep(1)
                s = await self.status()
                if s.connected:
                    return s
            return VPNStatus(connected=False, config_file=str(cfg), error="Connection timeout")
        except Exception as e:
            return VPNStatus(connected=False, error=str(e))

    async def disconnect(self) -> VPNStatus:
        pid = self._read_pid()
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
                for _ in range(10):
                    try:
                        os.kill(pid, 0)
                        await asyncio.sleep(0.5)
                    except OSError:
                        break
            except OSError:
                proc = await asyncio.create_subprocess_exec(
                    "sudo", "kill", str(pid),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()
        VPN_PID_FILE.unlink(missing_ok=True)
        return VPNStatus(connected=False)

    async def status(self) -> VPNStatus:
        pid = self._read_pid()
        if not pid:
            return VPNStatus(connected=False)
        try:
            os.kill(pid, 0)
        except OSError:
            VPN_PID_FILE.unlink(missing_ok=True)
            return VPNStatus(connected=False)
        local_ip = None
        if VPN_LOG_FILE.exists():
            log = VPN_LOG_FILE.read_text()
            m = re.search(r"IFCONFIG\s+(?:tun\d+\s+)?(\d+\.\d+\.\d+\.\d+)", log)
            if m:
                local_ip = m.group(1)
        return VPNStatus(connected=True, pid=pid, local_ip=local_ip, remote_ip="bastion.er.kcl.ac.uk")

    def get_log_tail(self, lines: int = 50) -> str:
        if not VPN_LOG_FILE.exists():
            return "No VPN log file."
        all_lines = VPN_LOG_FILE.read_text().splitlines()
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

    @staticmethod
    def _read_pid() -> Optional[int]:
        if not VPN_PID_FILE.exists():
            return None
        try:
            return int(VPN_PID_FILE.read_text().strip())
        except (ValueError, OSError):
            return None
