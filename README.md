# kcl-eresearch-mcp

**Fully automated MCP server for KCL e-Research Portal** — zero-intervention MFA, VPN, and SSH for CREATE HPC.

[中文文档](#中文文档)

---

## The Problem

When AI agents (Claude Code, Codex, etc.) SSH into CREATE HPC from a mobile hotspot, every IP change triggers a new MFA approval request. You end up:

1. Agent SSHs → MFA triggered → you approve on phone
2. Agent opens parallel SSH → IP changed → new MFA
3. Agent says "not responding" → you check portal → wrong IP → approve again
4. Repeat 10x

## The Solution

This MCP server eliminates all of that. It automates the entire chain:

```
Agent: "check TIMELY-Bench results on CREATE"

1. er_diagnose        → SSH failed, MFA needed, no VPN
2. er_vpn_connect     → Stable tunnel IP established
3. er_mfa_approve     → Auto-detect IP, API approve (~50ms, no browser)
4. er_ssh_run "ls ~/scratch/results/"
5. er_scp_transfer    → Download results locally

Session expired? Auto re-login via Playwright → SSO → TOTP.
Zero human intervention.
```

## Architecture

```
Agent (Claude Code / Codex)
  │ stdio
  ▼
kcl-eresearch-mcp server
  ├── auth.py        Playwright auto-SSO + pyotp TOTP → session cookies
  ├── portal.py      httpx → Laravel API (/api/internal/mfa/approve|reject)
  ├── vpn.py         OpenVPN connect/disconnect/status
  └── ssh_helper.py  SSH ControlMaster + MFA-aware retry
```

**Playwright is used ONLY for SSO login** (~once per 2h session). All MFA operations use httpx against the Laravel API (~50ms each).

## Quick Start

### 1. Install

```bash
pip install -e .
playwright install chromium
```

### 2. Set Credentials

Add to `~/.zshrc` or `~/.bashrc`:

```bash
export KCL_EMAIL="k1234567@kcl.ac.uk"
export KCL_PASSWORD="your_password"
export KCL_TOTP_SECRET="your_base32_totp_secret"
```

### 3. (Optional) Place VPN Config

```bash
mkdir -p ~/.kcl-er-mcp/vpn-configs
cp ~/Downloads/kcl-*.ovpn ~/.kcl-er-mcp/vpn-configs/
```

### 4. Register with Your Agent

**Claude Code:**

```bash
claude mcp add --scope user kcl-er \
  -e KCL_EMAIL="k1234567@kcl.ac.uk" \
  -e KCL_PASSWORD="your_password" \
  -e KCL_TOTP_SECRET="your_totp_secret" \
  -- python -m kcl_er_mcp.server
```

**Codex:**

```bash
codex mcp add kcl-er \
  --env KCL_EMAIL="k1234567@kcl.ac.uk" \
  --env KCL_PASSWORD="your_password" \
  --env KCL_TOTP_SECRET="your_totp_secret" \
  -- python -m kcl_er_mcp.server
```

## Getting Your TOTP Secret

The `KCL_TOTP_SECRET` is the base32 secret used to generate TOTP codes. To obtain it:

1. Go to [https://mysignins.microsoft.com](https://mysignins.microsoft.com) and re-enroll MFA
2. Choose **"I want to use a different authenticator app"**
3. Click **"Can't scan image?"** to reveal the secret key
4. That string is your `KCL_TOTP_SECRET`

Or use a TOTP app that displays the raw secret (e.g., Authy, KeePassXC).

## Tools (22 total) + Resources (5 total)

### Read-only Resources

These are intended for passive status reads and lightweight clients:

| Resource | Description |
|----------|-------------|
| `er://current-ip` | Current public IP as JSON |
| `er://session` | Portal session validity snapshot |
| `er://mfa-status` | MFA entries + current IP approval status |
| `er://diagnose` | Full connectivity diagnosis snapshot |
| `er://health` | Server uptime, log file, and timeout/error counters |

### Auth

| Tool | Description |
|------|-------------|
| `er_login` | Force SSO re-login (normally automatic) |
| `er_session_check` | Test if the current portal session is valid |
| `er_prepare_create` | One-call preparation: refresh session, approve current IP, then probe SSH |

### MFA (pure API, no browser, ~50ms)

| Tool | Description |
|------|-------------|
| `er_mfa_status` | List all MFA entries + check current IP status |
| `er_mfa_approve` | Approve an IP (auto-detects current IP if omitted) |
| `er_mfa_approve_all` | Approve ALL pending requests in one shot |
| `er_mfa_revoke` | Revoke an approved/pending IP |

### VPN

| Tool | Description |
|------|-------------|
| `er_vpn_status` | Check OpenVPN connection status |
| `er_vpn_connect` | Start VPN tunnel (requires `sudo` + `openvpn`) |
| `er_vpn_disconnect` | Stop VPN tunnel |
| `er_vpn_log` | View last 50 lines of OpenVPN log |

### SSH

| Tool | Description |
|------|-------------|
| `er_ssh_test` | Test SSH connectivity + MFA diagnosis |
| `er_ssh_run` | Execute a short command on CREATE HPC |
| `er_scp_transfer` | Upload/download files to/from CREATE |
| `er_ssh_setup` | Configure SSH ControlMaster in `~/.ssh/config` |
| `er_squeue` | Read Slurm queue state with a bounded, read-only query |
| `er_sacct` | Read Slurm accounting state for one job |
| `er_tail_file` | Tail a remote log or output file |
| `er_ls` | List a remote directory with bounded output |

### Utility

| Tool | Description |
|------|-------------|
| `er_current_ip` | Get current public IP address |
| `er_diagnose` | Full diagnostic: IP → session → VPN → SSH → MFA with fix recommendations |
| `er_health` | Inspect local server health, log files, and recent timeout/error counters |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `KCL_EMAIL` | Yes | Your k-number email (e.g., `k1234567@kcl.ac.uk`) |
| `KCL_PASSWORD` | Yes | KCL account password |
| `KCL_TOTP_SECRET` | Yes | TOTP base32 secret from authenticator setup |
| `KCL_K_NUMBER` | No | Override k-number (default: extracted from email) |
| `KCL_ER_OVPN_CONFIG` | No | Custom path to `.ovpn` file |
| `KCL_ER_HEADLESS` | No | Set `"0"` for visible browser (debug mode) |
| `KCL_ER_LOG_LEVEL` | No | `DEBUG` / `INFO` / `WARNING` |

## Security

- Credentials are **never stored on disk** — only passed via environment variables
- Session cookies saved to `~/.kcl-er-mcp/session.json` (chmod 600)
- Browser state in `~/.kcl-er-mcp/browser-state/` (for SSO cookie reuse)
- `.ovpn` files, `session.json`, and `browser-state/` are gitignored
- **TOTP secret is equivalent to having your authenticator app — protect it accordingly**

## Before vs After

**Before:**

> Agent SSHs → MFA triggered → you approve on phone → agent opens parallel SSH → IP changed → new MFA → agent says "not responding" → you check portal → wrong IP → approve again → repeat 10x

**After:**

> Agent calls `er_vpn_connect` + `er_mfa_approve` → done. All subsequent SSH/SCP reuse one ControlMaster socket through stable VPN IP. Zero MFA churn.

## Monitoring Guidance

- Use `er_squeue`, `er_sacct`, `er_tail_file`, and `er_ls` for repeated monitoring.
- Keep `er_ssh_run` for short RPC-style commands, not long polling loops such as `sleep 60 && ...`.
- If you really need a slower SSH command, pass an explicit larger `timeout`.
- Use `er_prepare_create` instead of chaining `er_session_check` → `er_mfa_status` → `er_mfa_approve` → `er_ssh_test`.

## Observability

- Server logs now live under `~/.kcl-er-mcp/logs/server.log`.
- Structured call and SSH/SCP result events are appended to `~/.kcl-er-mcp/logs/events.jsonl`.
- Use `er_health` or `er://health` to inspect uptime, recent timeout counters, and log file sizes.

## License

MIT

---

# 中文文档

## kcl-eresearch-mcp

**全自动 KCL e-Research Portal MCP 服务器** — 零人工干预的 MFA 审批、VPN 管理和 SSH 连接，专为 CREATE HPC 设计。

## 痛点

当 AI 智能体（Claude Code、Codex 等）通过手机热点 SSH 登录 CREATE HPC 时，每次 IP 变化都会触发新的 MFA 审批请求：

1. 智能体 SSH 连接 → 触发 MFA → 你在手机上批准
2. 智能体开启另一个 SSH → IP 变了 → 又触发 MFA
3. 智能体提示"无响应" → 你打开 Portal → 发现 IP 不对 → 重新批准
4. 重复 10 次...

## 解决方案

本 MCP 服务器自动化了整个流程：

```
智能体："检查 CREATE 上的 TIMELY-Bench 结果"

1. er_diagnose        → SSH 失败，需要 MFA，没有 VPN
2. er_vpn_connect     → 建立稳定的 VPN 隧道 IP
3. er_mfa_approve     → 自动检测 IP，API 审批（~50ms，无需浏览器）
4. er_ssh_run "ls ~/scratch/results/"
5. er_scp_transfer    → 下载结果到本地

Session 过期？自动重新登录：Playwright → SSO → TOTP。
全程零人工干预。
```

## 架构

```
智能体（Claude Code / Codex）
  │ stdio
  ▼
kcl-eresearch-mcp 服务器
  ├── auth.py        Playwright 自动 SSO + pyotp TOTP → session cookies
  ├── portal.py      httpx → Laravel API（/api/internal/mfa/approve|reject）
  ├── vpn.py         OpenVPN 连接/断开/状态查询
  └── ssh_helper.py  SSH ControlMaster + MFA 感知重试
```

**Playwright 仅用于 SSO 登录**（约每 2 小时一次）。所有 MFA 操作使用 httpx 直接调用 Laravel API（每次约 50ms）。

## 快速开始

### 1. 安装

```bash
pip install -e .
playwright install chromium
```

### 2. 设置凭据

添加到 `~/.zshrc` 或 `~/.bashrc`：

```bash
export KCL_EMAIL="k1234567@kcl.ac.uk"
export KCL_PASSWORD="你的密码"
export KCL_TOTP_SECRET="你的_base32_TOTP密钥"
```

### 3.（可选）放置 VPN 配置

```bash
mkdir -p ~/.kcl-er-mcp/vpn-configs
cp ~/Downloads/kcl-*.ovpn ~/.kcl-er-mcp/vpn-configs/
```

### 4. 注册到智能体

**Claude Code：**

```bash
claude mcp add --scope user kcl-er \
  -e KCL_EMAIL="k1234567@kcl.ac.uk" \
  -e KCL_PASSWORD="你的密码" \
  -e KCL_TOTP_SECRET="你的TOTP密钥" \
  -- python -m kcl_er_mcp.server
```

**Codex：**

```bash
codex mcp add kcl-er \
  --env KCL_EMAIL="k1234567@kcl.ac.uk" \
  --env KCL_PASSWORD="你的密码" \
  --env KCL_TOTP_SECRET="你的TOTP密钥" \
  -- python -m kcl_er_mcp.server
```

## 获取 TOTP 密钥

`KCL_TOTP_SECRET` 是用于生成 TOTP 验证码的 base32 密钥。获取方法：

1. 前往 [https://mysignins.microsoft.com](https://mysignins.microsoft.com)，重新注册 MFA
2. 选择 **"我想使用其他身份验证器应用"**
3. 点击 **"无法扫描图像？"** 以显示密钥
4. 该字符串即为你的 `KCL_TOTP_SECRET`

也可以使用能显示原始密钥的 TOTP 应用（如 Authy、KeePassXC）。

## 工具列表（共 22 个）+ 资源（共 5 个）

### 只读资源

| 资源 | 说明 |
|------|------|
| `er://current-ip` | 当前公网 IP 的 JSON 快照 |
| `er://session` | Portal 会话有效性快照 |
| `er://mfa-status` | MFA 条目和当前 IP 审批状态 |
| `er://diagnose` | 全链路连接诊断快照 |
| `er://health` | 服务 uptime、日志文件和 timeout/error 计数器 |

### 认证

| 工具 | 说明 |
|------|------|
| `er_login` | 强制 SSO 重新登录（通常自动执行） |
| `er_session_check` | 检测当前 Portal 会话是否有效 |
| `er_prepare_create` | 一次性完成会话刷新、当前 IP 审批和 SSH 探测 |

### MFA（纯 API，无需浏览器，约 50ms）

| 工具 | 说明 |
|------|------|
| `er_mfa_status` | 列出所有 MFA 条目 + 检查当前 IP 状态 |
| `er_mfa_approve` | 审批某个 IP（省略时自动检测当前 IP） |
| `er_mfa_approve_all` | 一次性审批所有待处理请求 |
| `er_mfa_revoke` | 撤销某个已审批/待处理的 IP |

### VPN

| 工具 | 说明 |
|------|------|
| `er_vpn_status` | 检查 OpenVPN 连接状态 |
| `er_vpn_connect` | 启动 VPN 隧道（需要 `sudo` + `openvpn`） |
| `er_vpn_disconnect` | 断开 VPN 隧道 |
| `er_vpn_log` | 查看 OpenVPN 最近 50 行日志 |

### SSH

| 工具 | 说明 |
|------|------|
| `er_ssh_test` | 测试 SSH 连通性 + MFA 诊断 |
| `er_ssh_run` | 在 CREATE HPC 上执行短命令 |
| `er_scp_transfer` | 上传/下载文件至 CREATE |
| `er_ssh_setup` | 在 `~/.ssh/config` 中配置 SSH ControlMaster |
| `er_squeue` | 以有界只读方式查询 Slurm 队列 |
| `er_sacct` | 查询单个作业的 Slurm accounting 状态 |
| `er_tail_file` | 查看远端日志或输出文件尾部 |
| `er_ls` | 以有界输出列出远端目录 |

### 实用工具

| 工具 | 说明 |
|------|------|
| `er_current_ip` | 获取当前公网 IP |
| `er_diagnose` | 全面诊断：IP → 会话 → VPN → SSH → MFA，并给出修复建议 |
| `er_health` | 查看本地服务健康状态、日志文件和最近的 timeout/error 计数器 |

## 环境变量

| 变量 | 必填 | 说明 |
|------|------|------|
| `KCL_EMAIL` | 是 | k-number 邮箱（如 `k1234567@kcl.ac.uk`） |
| `KCL_PASSWORD` | 是 | KCL 账户密码 |
| `KCL_TOTP_SECRET` | 是 | TOTP base32 密钥 |
| `KCL_K_NUMBER` | 否 | 手动指定 k-number（默认从邮箱提取） |
| `KCL_ER_OVPN_CONFIG` | 否 | `.ovpn` 文件自定义路径 |
| `KCL_ER_HEADLESS` | 否 | 设为 `"0"` 显示浏览器（调试模式） |
| `KCL_ER_LOG_LEVEL` | 否 | `DEBUG` / `INFO` / `WARNING` |

## 安全性

- 凭据**绝不存储在磁盘上** — 仅通过环境变量传递
- Session cookies 保存在 `~/.kcl-er-mcp/session.json`（权限 chmod 600）
- 浏览器状态保存在 `~/.kcl-er-mcp/browser-state/`（用于 SSO cookie 复用）
- `.ovpn` 文件、`session.json` 和 `browser-state/` 均已添加到 `.gitignore`
- **TOTP 密钥等同于你的身份验证器 — 请妥善保管**

## 使用前后对比

**使用前：**

> 智能体 SSH → 触发 MFA → 手机审批 → 智能体开新连接 → IP 变了 → 又触发 MFA → 智能体提示超时 → 打开 Portal → IP 不对 → 重新审批 → 重复 10 次

**使用后：**

> 智能体调用 `er_vpn_connect` + `er_mfa_approve` → 搞定。后续所有 SSH/SCP 复用同一个 ControlMaster socket，通过稳定的 VPN IP 连接。MFA 零干扰。

## 监控建议

- 高频监控优先用 `er_squeue`、`er_sacct`、`er_tail_file` 和 `er_ls`。
- `er_ssh_run` 保留给短 RPC，不要再拿来做 `sleep 60 && ...` 这类长轮询。
- 如果确实要跑更慢的 SSH 命令，显式传更大的 `timeout`。
- 会话准备优先用 `er_prepare_create`，不要反复串 `er_session_check`、`er_mfa_status`、`er_mfa_approve`、`er_ssh_test`。

## 可观测性

- 服务日志写入 `~/.kcl-er-mcp/logs/server.log`。
- 结构化调用事件与 SSH/SCP 结果写入 `~/.kcl-er-mcp/logs/events.jsonl`。
- 用 `er_health` 或 `er://health` 查看 uptime、最近 timeout 次数和日志文件大小。

## 许可证

MIT
