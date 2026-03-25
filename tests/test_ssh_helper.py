import asyncio

import pytest

from kcl_er_mcp.ssh_helper import SSHHelper


class FakeProc:
    def __init__(self, *, returncode=None, stdout=b"", stderr=b"", pid=1234):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self.pid = pid
        self.terminated = False
        self.killed = False
        self.communicate_calls = 0

    async def communicate(self):
        self.communicate_calls += 1
        return self._stdout, self._stderr

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


@pytest.mark.asyncio
async def test_run_command_timeout_cleans_up_and_is_not_mfa(monkeypatch):
    helper = SSHHelper(k_number="k1234567")
    proc = FakeProc(stdout=b"partial stdout", stderr=b"partial stderr")

    async def fake_create_subprocess_exec(*args, **kwargs):
        return proc

    wait_calls = 0

    async def fake_wait_for(awaitable, timeout):
        nonlocal wait_calls
        wait_calls += 1
        if wait_calls == 1:
            awaitable.close()
            raise asyncio.TimeoutError()
        return await awaitable

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr(asyncio, "wait_for", fake_wait_for)

    result = await helper.run_command("sleep 65", timeout=1)

    assert result.success is False
    assert result.timed_out is True
    assert result.error_type == "timeout"
    assert result.mfa_needed is False
    assert result.stdout == "partial stdout"
    assert result.stderr == "partial stderr"
    assert proc.terminated is True
    assert proc.killed is False


@pytest.mark.asyncio
async def test_scp_timeout_cleans_up_and_preserves_partial_output(monkeypatch):
    helper = SSHHelper(k_number="k1234567")
    proc = FakeProc(stdout=b"copied some bytes", stderr=b"slow link")

    async def fake_create_subprocess_exec(*args, **kwargs):
        return proc

    wait_calls = 0

    async def fake_wait_for(awaitable, timeout):
        nonlocal wait_calls
        wait_calls += 1
        if wait_calls == 1:
            awaitable.close()
            raise asyncio.TimeoutError()
        return await awaitable

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr(asyncio, "wait_for", fake_wait_for)

    result = await helper.scp_download("/remote/file", "/tmp/local", timeout=1)

    assert result.success is False
    assert result.timed_out is True
    assert result.error_type == "timeout"
    assert result.stdout == "copied some bytes"
    assert result.stderr == "slow link"
    assert proc.terminated is True


@pytest.mark.asyncio
async def test_run_command_classifies_mfa_from_stderr(monkeypatch):
    helper = SSHHelper(k_number="k1234567")
    proc = FakeProc(returncode=255, stderr=b"Permission denied (publickey,password).")

    async def fake_create_subprocess_exec(*args, **kwargs):
        return proc

    async def fake_wait_for(awaitable, timeout):
        return await awaitable

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr(asyncio, "wait_for", fake_wait_for)

    result = await helper.run_command("hostname", timeout=5)

    assert result.success is False
    assert result.timed_out is False
    assert result.mfa_needed is True
    assert result.error_type == "mfa"
