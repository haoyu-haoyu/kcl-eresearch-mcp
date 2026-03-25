# Agent Usage Guide for kcl-eresearch-mcp

## Core Principle

This MCP server automates **MFA authentication and session management** for KCL CREATE HPC.
It does NOT replace direct SSH — after preparation, always prefer direct `ssh create` commands.

## Recommended Workflow

### Step 1: Prepare (once per session)

Call `er_prepare_create` — this does everything in one shot:
- Ensures `~/.ssh/config` has the `Host create` alias with ControlMaster
- Logs into the e-Research portal (auto SSO + TOTP)
- Approves your current IP for MFA
- Probes SSH to verify connectivity

### Step 2: Use direct SSH (all subsequent commands)

After `er_prepare_create` succeeds, run commands directly:

```bash
ssh create 'squeue -u $USER'
ssh create 'ls ~/scratch/results/'
ssh create 'cat ~/scratch/job.log'
scp create:~/scratch/output.csv ./output.csv
```

**Do NOT use `er_ssh_run` for routine commands.** Direct SSH is faster and does not require tool approval.

### Step 3: Handle failures

If direct SSH fails with "Permission denied" or "Connection refused":
1. Call `er_mfa_approve` to re-approve your IP
2. Then retry the direct SSH command

If the portal session expires (auto-detected):
1. Call `er_login` to force re-login
2. Then call `er_mfa_approve`

## When to use MCP tools vs direct SSH

| Task | Use |
|------|-----|
| First-time setup / MFA approval | `er_prepare_create` |
| Run commands on CREATE | `ssh create '<command>'` |
| Transfer files | `scp create:<remote> <local>` |
| SSH fails with MFA error | `er_mfa_approve` then retry SSH |
| Check MFA status | `er_mfa_status` |
| VPN management | `er_vpn_connect` / `er_vpn_disconnect` |
| Diagnose connectivity | `er_diagnose` |

## What NOT to do

- Do NOT use `er_ssh_run` for routine commands — use `ssh create` instead
- Do NOT chain `er_session_check` → `er_mfa_status` → `er_mfa_approve` → `er_ssh_test` — use `er_prepare_create` instead
- Do NOT poll with `er_ssh_run 'sleep 60 && ...'` — use direct SSH with explicit timeouts
