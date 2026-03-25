"""Lightweight observability helpers for the kcl-er MCP server."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATE_DIR = Path.home() / ".kcl-er-mcp"
LOG_DIR = STATE_DIR / "logs"
SERVER_LOG_FILE = LOG_DIR / "server.log"
EVENT_LOG_FILE = LOG_DIR / "events.jsonl"

REDACTED_KEYS = ("password", "secret", "token", "cookie", "session", "csrf")
MAX_STRING_LENGTH = 200
STARTED_AT = datetime.now(timezone.utc)

_LOCK = threading.Lock()
_METRICS = {
    "calls_total": 0,
    "tool_calls_total": 0,
    "resource_reads_total": 0,
    "call_failures_total": 0,
    "ssh_timeouts_total": 0,
    "scp_timeouts_total": 0,
    "last_timeout_at": None,
    "last_timeout_kind": None,
    "last_error_at": None,
    "last_error_kind": None,
    "last_call_name": None,
    "last_request_id": None,
}
_OBSERVABILITY_READY = False


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def setup_observability() -> None:
    global _OBSERVABILITY_READY
    if _OBSERVABILITY_READY:
        return

    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        return

    logger = logging.getLogger("kcl_er_mcp")
    if any(
        isinstance(handler, logging.FileHandler)
        and Path(getattr(handler, "baseFilename", "")) == SERVER_LOG_FILE
        for handler in logger.handlers
    ):
        _OBSERVABILITY_READY = True
        return

    level_name = os.environ.get("KCL_ER_LOG_LEVEL", "INFO").upper()
    try:
        handler = logging.FileHandler(SERVER_LOG_FILE)
    except OSError:
        return

    handler.setLevel(getattr(logging, level_name, logging.INFO))
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    )
    logger.addHandler(handler)
    _OBSERVABILITY_READY = True


def _sanitize(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        text = value.replace("\r", " ").replace("\n", " ").strip()
        return text[: MAX_STRING_LENGTH - 3] + "..." if len(text) > MAX_STRING_LENGTH else text
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "model_dump"):
        return _sanitize(value.model_dump())
    if is_dataclass(value):
        return _sanitize(asdict(value))
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            key_str = str(key)
            if any(marker in key_str.lower() for marker in REDACTED_KEYS):
                redacted[key_str] = "<redacted>"
            else:
                redacted[key_str] = _sanitize(item)
        return redacted
    if isinstance(value, (list, tuple, set)):
        return [_sanitize(item) for item in value]
    return _sanitize(str(value))


def _write_event(record: dict[str, Any]) -> None:
    setup_observability()
    if not _OBSERVABILITY_READY:
        return
    with _LOCK:
        try:
            with EVENT_LOG_FILE.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            return


def record_server_event(event: str, **fields: Any) -> None:
    _write_event(
        {
            "timestamp": _utc_now(),
            "event": event,
            "pid": os.getpid(),
            "fields": _sanitize(fields),
        }
    )


def start_call(kind: str, name: str, params: Any = None) -> tuple[str, float]:
    request_id = uuid.uuid4().hex[:12]
    with _LOCK:
        _METRICS["calls_total"] += 1
        if kind == "tool":
            _METRICS["tool_calls_total"] += 1
        else:
            _METRICS["resource_reads_total"] += 1
        _METRICS["last_call_name"] = name
        _METRICS["last_request_id"] = request_id

    _write_event(
        {
            "timestamp": _utc_now(),
            "event": "call_start",
            "request_id": request_id,
            "call_kind": kind,
            "name": name,
            "params": _sanitize(params),
        }
    )
    return request_id, time.perf_counter()


def finish_call(
    kind: str,
    name: str,
    request_id: str,
    started_at: float,
    *,
    status: str,
    result: Any = None,
    error: Any = None,
) -> None:
    duration_ms = round((time.perf_counter() - started_at) * 1000, 2)
    if status != "ok":
        with _LOCK:
            _METRICS["call_failures_total"] += 1
            _METRICS["last_error_at"] = _utc_now()
            _METRICS["last_error_kind"] = f"{kind}:{name}"

    payload = {
        "timestamp": _utc_now(),
        "event": "call_end",
        "request_id": request_id,
        "call_kind": kind,
        "name": name,
        "status": status,
        "duration_ms": duration_ms,
    }
    if result is not None:
        payload["result"] = _sanitize(result)
    if error is not None:
        payload["error"] = _sanitize(error)
    _write_event(payload)


def record_remote_exec(
    kind: str,
    *,
    command: str,
    timeout: int,
    pid: int | None,
    return_code: int | None,
    timed_out: bool,
    error_type: str | None,
    stderr: str = "",
) -> None:
    if timed_out:
        with _LOCK:
            _METRICS[f"{kind}_timeouts_total"] += 1
            _METRICS["last_timeout_at"] = _utc_now()
            _METRICS["last_timeout_kind"] = kind
    elif error_type:
        with _LOCK:
            _METRICS["last_error_at"] = _utc_now()
            _METRICS["last_error_kind"] = f"{kind}:{error_type}"

    _write_event(
        {
            "timestamp": _utc_now(),
            "event": f"{kind}_result",
            "command": _sanitize(command),
            "timeout": timeout,
            "pid": pid,
            "return_code": return_code,
            "timed_out": timed_out,
            "error_type": error_type,
            "stderr": _sanitize(stderr),
        }
    )


def get_health_snapshot() -> dict[str, Any]:
    setup_observability()
    with _LOCK:
        metrics = dict(_METRICS)

    def file_info(path: Path) -> dict[str, Any]:
        try:
            exists = path.exists()
        except OSError:
            exists = False
        if not exists:
            return {"path": str(path), "exists": False, "size_bytes": 0}
        return {
            "path": str(path),
            "exists": True,
            "size_bytes": path.stat().st_size,
        }

    return {
        "pid": os.getpid(),
        "started_at": STARTED_AT.isoformat().replace("+00:00", "Z"),
        "uptime_seconds": int((datetime.now(timezone.utc) - STARTED_AT).total_seconds()),
        "log_dir": str(LOG_DIR),
        "observability_ready": _OBSERVABILITY_READY,
        "server_log": file_info(SERVER_LOG_FILE),
        "event_log": file_info(EVENT_LOG_FILE),
        "metrics": metrics,
    }
