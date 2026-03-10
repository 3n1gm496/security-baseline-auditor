# security-baseline-auditor

**Defensive, read-only local security audit tool for Linux, macOS and Windows.**

`security-baseline-auditor` (`sbaudit`) is a CLI tool that performs a comprehensive security baseline audit on the local machine. It does **not** execute exploits, brute-force attacks, or scan remote hosts. It works entirely in read-only mode on the local system.

---

## Features

| Feature | Description |
|---------|-------------|
| **Host Information** | Hostname, OS, kernel, uptime, local users, installed security tools |
| **Network Exposure** | Listening ports with PID, process, user, executable path; highlights public bindings |
| **Hardening Checks** | 18 Linux, 12 Windows, 10 macOS real checks (SSH, firewall, encryption, policies...) |
| **Secret Scanner** | Detects AWS keys, GitHub/GitLab tokens, PEM keys, .env files, hardcoded credentials |
| **File Permissions** | World-writable files, insecure private keys, modifiable startup scripts |
| **Risk Scoring** | 0-100 score with explainable formula and risk labels (LOW/MODERATE/HIGH/CRITICAL) |
| **Multi-format Reports** | Console (colored), JSON, HTML (elegant), Markdown (Jira/Confluence-ready) |
| **Cross-platform** | Linux, macOS, Windows — modular OS-specific plugins |

---

## Installation

### From source (recommended)

```bash
git clone https://github.com/3n1gm496/security-baseline-auditor.git
cd security-baseline-auditor
pip install -e .
```

### Using pip (once published)

```bash
pip install security-baseline-auditor
```

---

## Usage

### Basic audit (full mode, console output)

```bash
sbaudit
```

### Quick mode (faster, subset of checks)

```bash
sbaudit --quick
```

### Export to JSON

```bash
sbaudit --format json --output ./reports
```

### Export to HTML

```bash
sbaudit --format html --output ./reports
```

### Export to Markdown

```bash
sbaudit --format md --output ./reports
```

### Scan specific paths for secrets

```bash
sbaudit --paths /home/deploy /opt/app --exclude "*.log" "/tmp"
```

### Filter by severity

```bash
sbaudit --severity-threshold high
```

### Verbose mode

```bash
sbaudit -v
```

---

## CLI Reference

```
usage: sbaudit [-h] [--version] [--quick | --full] [--paths PATHS [PATHS ...]]
               [--exclude EXCLUDE [EXCLUDE ...]] [--format {json,html,md}]
               [--output OUTPUT] [--severity-threshold SEVERITY] [-v]

security-baseline-auditor — Defensive, read-only local security audit tool
for Linux, macOS and Windows.

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --quick               Run only quick checks (subset of full audit).
  --full                Run all checks (default).
  --paths PATHS [PATHS ...]
                        Directories to scan for secrets and file permissions.
  --exclude EXCLUDE [EXCLUDE ...]
                        Directories or patterns to exclude from scanning.
  --format {json,html,md}
                        Export format (in addition to console output).
  --output OUTPUT       Output directory for exported reports.
  --severity-threshold SEVERITY
                        Minimum severity to report (info, low, medium, high, critical).
  -v, --verbose         Enable verbose/debug logging.
```

**Exit codes:**
- `0` — No HIGH or CRITICAL findings
- `1` — HIGH or CRITICAL findings detected
- `2` — Audit failed with error

---

## Checks Reference

### Linux (18 checks)

| ID | Title | Severity |
|----|-------|----------|
| LIN-001 | SSH: PermitRootLogin | HIGH |
| LIN-002 | SSH: PasswordAuthentication | MEDIUM |
| LIN-003 | SSH: Protocol version | CRITICAL |
| LIN-004 | SSH: X11Forwarding | LOW |
| LIN-005 | Sudoers: NOPASSWD entries | MEDIUM |
| LIN-006 | /etc/shadow permissions | CRITICAL |
| LIN-007 | Firewall status (UFW/firewalld/iptables) | HIGH |
| LIN-008 | SUID/SGID suspicious binaries | MEDIUM |
| LIN-009 | Risky enabled services | MEDIUM |
| LIN-010 | Kernel: IP forwarding | MEDIUM |
| LIN-011 | Core dumps restriction | LOW |
| LIN-012 | /tmp mount options | LOW |
| LIN-013 | Automatic security updates | MEDIUM |
| LIN-014 | Password policy (min length) | MEDIUM |
| LIN-015 | SSH: MaxAuthTries | LOW |
| LIN-016 | /etc/passwd permissions | CRITICAL |
| LIN-017 | Kernel: ASLR | HIGH |
| LIN-018 | Login banner | LOW |

### Windows (12 checks)

| ID | Title | Severity |
|----|-------|----------|
| WIN-001 | Windows Defender real-time protection | CRITICAL |
| WIN-002 | Windows Firewall profiles | HIGH |
| WIN-003 | RDP status | MEDIUM |
| WIN-004 | PowerShell execution policy | HIGH |
| WIN-005 | BitLocker encryption | HIGH |
| WIN-006 | Guest account status | MEDIUM |
| WIN-007 | AutoRun/AutoPlay | MEDIUM |
| WIN-008 | SMBv1 protocol | CRITICAL |
| WIN-009 | Windows Update service | MEDIUM |
| WIN-010 | Audit policy: logon events | MEDIUM |
| WIN-011 | Screen lock timeout | LOW |
| WIN-012 | Remote Registry service | MEDIUM |

### macOS (10 checks)

| ID | Title | Severity |
|----|-------|----------|
| MAC-001 | FileVault disk encryption | HIGH |
| MAC-002 | Application firewall | HIGH |
| MAC-003 | Firewall stealth mode | LOW |
| MAC-004 | Automatic login | HIGH |
| MAC-005 | Screen saver password | MEDIUM |
| MAC-006 | Remote Login (SSH) | MEDIUM |
| MAC-007 | Gatekeeper | HIGH |
| MAC-008 | System Integrity Protection (SIP) | CRITICAL |
| MAC-009 | Third-party Launch Agents/Daemons | LOW |
| MAC-010 | Automatic software updates | MEDIUM |

---

## Risk Scoring Formula

The risk score is calculated as follows:

```
raw = sum(severity.score for each FAIL/WARN finding)
    + sum(severity.score for each secret found)
    + sum(severity.score for each file permission issue)

risk_score = min(100, raw * 100 / 50)
```

**Severity weights:**

| Severity | Score |
|----------|-------|
| INFO | 0 |
| LOW | 1 |
| MEDIUM | 3 |
| HIGH | 5 |
| CRITICAL | 10 |

**Risk labels:**

| Score Range | Label |
|-------------|-------|
| 0–10 | LOW |
| 11–30 | MODERATE |
| 31–60 | HIGH |
| 61–100 | CRITICAL |

---

## Secret Patterns Detected

The scanner detects the following patterns with partial masking (secrets are never fully printed):

- AWS Access Keys (`AKIA...`)
- AWS Secret Keys
- GitHub Personal Access Tokens (`ghp_...`)
- GitLab Personal Access Tokens (`glpat-...`)
- Generic API keys and secrets
- PEM Private Keys
- Slack Tokens (`xox...`)
- Stripe Keys (`sk_live_...`)
- Google API Keys (`AIza...`)
- Heroku API Keys
- JWT Tokens
- Database connection strings with credentials

---

## Project Structure

```
security-baseline-auditor/
├── auditor/
│   ├── __init__.py          # Package version
│   ├── cli.py               # CLI entry point (sbaudit)
│   ├── models.py            # Data models (Finding, HostInfo, AuditResult...)
│   ├── checks/
│   │   ├── linux/
│   │   │   └── hardening.py # 18 Linux hardening checks
│   │   ├── windows/
│   │   │   └── hardening.py # 12 Windows hardening checks
│   │   ├── macos/
│   │   │   └── hardening.py # 10 macOS hardening checks
│   │   ├── secrets.py       # Secret exposure scanner
│   │   └── file_permissions.py # File permissions audit
│   ├── collectors/
│   │   ├── host_info.py     # Host information collector
│   │   └── network.py       # Network exposure collector
│   ├── reporters/
│   │   ├── console.py       # Colored console output
│   │   ├── json_reporter.py # JSON export
│   │   ├── html_reporter.py # HTML report
│   │   └── markdown_reporter.py # Markdown export
│   ├── rules/
│   │   └── engine.py        # Check registry and rule engine
│   └── utils/
│       └── platform.py      # OS detection, command execution
├── tests/
│   ├── test_models.py       # Model unit tests
│   ├── test_engine.py       # Rule engine tests
│   ├── test_secrets.py      # Secret scanner tests
│   ├── test_reporters.py    # Reporter tests
│   └── test_cli.py          # CLI parser tests
├── samples/                 # Sample reports
├── pyproject.toml           # Package configuration
├── LICENSE                  # MIT License
└── README.md                # This file
```

---

## Security Principles

This tool follows strict defensive security principles:

- **Read-only by default** — never modifies the system
- **No automatic remediation** — only reports and recommends
- **No data upload** — all data stays local
- **No telemetry** — no tracking or analytics
- **No unnecessary dependencies** — stdlib-only, zero external deps
- **No remote scanning** — works exclusively on the local machine
- **Partial secret masking** — never prints full credentials

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Development

```bash
# Install in development mode
pip install -e .

# Run the tool
sbaudit --quick -v

# Run tests
pytest tests/ -v

# Type checking (optional)
pip install mypy
mypy auditor/
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
