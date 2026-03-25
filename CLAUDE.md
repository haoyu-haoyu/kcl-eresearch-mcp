# KCL e-Research MCP Server

Fully automated MFA, VPN, and SSH management for CREATE HPC.

## Workflow

1. Call `er_prepare_create` once — handles SSH config, portal login, MFA approval, SSH probe
2. After success, use direct SSH for ALL commands:
   ```bash
   ssh create '<command>'
   scp create:<remote_path> <local_path>
   ```
3. Do NOT use `er_ssh_run` for routine commands — direct `ssh create` is faster and needs no tool approval
4. If SSH fails with "Permission denied", call `er_mfa_approve` then retry direct SSH

## Tool Categories

### Use these MCP tools (auth/network management):
- `er_prepare_create` — one-call setup (session + MFA + SSH config + probe)
- `er_mfa_approve` / `er_mfa_approve_all` — approve IP for MFA
- `er_mfa_status` — check MFA entries
- `er_vpn_connect` / `er_vpn_disconnect` — VPN tunnel management
- `er_diagnose` — full connectivity diagnostic
- `er_health` — server health check

### Prefer direct SSH over these tools:
- `er_ssh_run` — fallback only, prefer `ssh create '<cmd>'`
- `er_squeue` / `er_sacct` — prefer `ssh create 'squeue ...'`
- `er_tail_file` / `er_ls` — prefer `ssh create 'tail ...'` / `ssh create 'ls ...'`
- `er_scp_transfer` — prefer `scp create:<path> <local>`

## Anti-patterns
- Do NOT chain `er_session_check` → `er_mfa_status` → `er_mfa_approve` → `er_ssh_test` — use `er_prepare_create`
- Do NOT poll with `er_ssh_run 'sleep 60 && ...'` — use direct SSH with timeouts
- Do NOT use `er_ssh_run` when `ssh create` works — it adds unnecessary tool-call overhead
