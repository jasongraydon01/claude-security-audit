# Security Audit Skills for Claude Code

Comprehensive, framework-agnostic security audit skills for Claude Code. Run thorough security audits on any codebase with a simple command.

## Two Skill Variants

This repository includes **two versions** of the security audit skill. Choose based on your needs:

| Skill | Best For | Trade-off |
|-------|----------|-----------|
| `security-audit` | Pre-launch audits, compliance prep, comprehensive review | More thorough (multi-agent), uses more tokens |
| `security-audit-quick` | Quick checks, regular scans, CI integration | Faster, more token-efficient (single-pass) |

**In testing, the full multi-agent version uncovered additional findings that the quick version missed.** Both are valid choices depending on your situation - install one or both.

---

## Overview

These skills enable Claude to perform professional-grade security audits on any codebase. They use a **discovery-first approach** - detecting your tech stack before applying relevant security patterns, ensuring accurate and relevant findings whether you're running Node.js, Python, Ruby, Go, mobile apps, or anything else.

### Key Features

- **Framework-Agnostic**: Works on any codebase - Node.js, Python, Ruby, Go, Rust, Java, .NET, mobile (React Native, Flutter, Swift, Kotlin), and more
- **Discovery-First**: Automatically detects your tech stack, architecture, and security-relevant configurations
- **Automated Scanning**: Runs deterministic checks for secrets, vulnerable dependencies, and common vulnerabilities
- **Current Threat Intelligence**: Searches for recent CVEs and vulnerabilities specific to your stack
- **AI-Powered Review**: Performs targeted code review based on discovered patterns
- **Persistent History**: Tracks audit results over time for comparison
- **Actionable Reports**: Generates executive summaries, detailed findings, and remediation plans

### What It Detects

| Category | Examples |
|----------|----------|
| **Secrets** | API keys, tokens, passwords, private keys, connection strings |
| **Injection** | SQL, NoSQL, command, XSS, SSRF, template injection |
| **Authentication** | Missing auth, weak sessions, JWT issues, OAuth misconfigs |
| **Authorization** | IDOR, privilege escalation, broken access control |
| **Cryptography** | Weak hashing, hardcoded keys, improper TLS |
| **Dependencies** | Known CVEs in packages |
| **Configuration** | Debug mode, missing headers, exposed endpoints |
| **AI/LLM Security** | Prompt injection, API key exposure, output validation |

---

## Installation

### Option 1: Install Both Skills (Recommended)

Clone and copy both skill folders to your project:

```bash
git clone https://github.com/jasongraydon01/claude-security-audit.git

# Install full (multi-agent) version
mkdir -p your-project/.claude/skills/security-audit
cp -r claude-security-audit/security-audit/* your-project/.claude/skills/security-audit/

# Install quick (single-pass) version
mkdir -p your-project/.claude/skills/security-audit-quick
cp -r claude-security-audit/security-audit-quick/* your-project/.claude/skills/security-audit-quick/
```

### Option 2: Install One Skill

**Full version only:**
```bash
git clone https://github.com/jasongraydon01/claude-security-audit.git
mkdir -p your-project/.claude/skills/security-audit
cp -r claude-security-audit/security-audit/* your-project/.claude/skills/security-audit/
```

**Quick version only:**
```bash
git clone https://github.com/jasongraydon01/claude-security-audit.git
mkdir -p your-project/.claude/skills/security-audit-quick
cp -r claude-security-audit/security-audit-quick/* your-project/.claude/skills/security-audit-quick/
```

### Global Installation

Install globally to use across all projects:

```bash
git clone https://github.com/jasongraydon01/claude-security-audit.git

# Full version
mkdir -p ~/.claude/skills/security-audit
cp -r claude-security-audit/security-audit/* ~/.claude/skills/security-audit/

# Quick version
mkdir -p ~/.claude/skills/security-audit-quick
cp -r claude-security-audit/security-audit-quick/* ~/.claude/skills/security-audit-quick/
```

### Expected Structure

After installation:
```
your-project/
└── .claude/
    └── skills/
        ├── security-audit/           # Full multi-agent version
        │   ├── SKILL.md
        │   ├── references/
        │   ├── scripts/
        │   └── templates/
        └── security-audit-quick/     # Quick single-pass version
            ├── SKILL.md
            ├── references/
            ├── scripts/
            └── templates/
```

---

## Usage

### Full Audit (Multi-Agent)

```
Run a security audit
```

Claude will spawn multiple specialized agents to deeply analyze:
- Authentication & session management
- Authorization & access control
- Input validation & injection
- Secrets & configuration
- Cryptography & data protection
- Stack-specific vulnerabilities

### Quick Audit (Single-Pass)

```
Run a quick security scan
```

Claude will perform a streamlined single-pass audit covering all major security areas efficiently.

### When to Use Each

| Scenario | Recommended Skill |
|----------|-------------------|
| Pre-launch security review | `security-audit` (full) |
| Compliance preparation | `security-audit` (full) |
| Regular weekly/monthly checks | `security-audit-quick` |
| Quick sanity check before PR | `security-audit-quick` |
| Limited token budget | `security-audit-quick` |
| Found something concerning, need deeper look | `security-audit` (full) |

### Other Commands

```
Run a security audit focusing on authentication
```

```
Check for hardcoded secrets
```

```
Compare this audit to the previous one
```

```
Show our security history
```

```
Create a remediation plan for the critical findings
```

---

## What Gets Created

On first run, the skill creates a `.security-audit/` directory in your project:

```
.security-audit/
├── stack-profile.json      # Detected technology stack
├── project-context.json    # Your answers to grounding questions
├── audit-history.json      # Historical audit data
├── scan-results/           # Raw scan outputs
│   ├── secrets.json
│   ├── dependencies.json
│   ├── auth.json
│   └── input-flows.json
└── findings/               # Generated reports
    ├── audit-2025-01-06.md
    └── summary-2025-01-06.md
```

**Note**: Consider adding `.security-audit/` to your `.gitignore` if the findings contain sensitive information.

---

## Customization

### Adding Stack-Specific Patterns

Create new files in `references/stacks/` following the existing format:

```markdown
# FRAMEWORK_NAME.md

## Common Vulnerabilities
...

## Framework-Specific Misconfigurations
...

## Security Features Often Missed
...
```

### Adjusting Severity

Edit `references/SEVERITY_GUIDE.md` to calibrate severity ratings for your organization's risk tolerance.

### Custom Secret Patterns

Add patterns to `scripts/secret_scanner.py` in the `SECRET_PATTERNS` dictionary.

---

## Requirements

### Python Scripts
- Python 3.8+
- Standard library only (no pip install required)

### Dependency Auditing
For full dependency scanning, install the appropriate tools:

| Package Manager | Tool |
|-----------------|------|
| npm/yarn/pnpm | Built-in (`npm audit`) |
| pip | `pip install pip-audit` or `pip install safety` |
| bundler | `gem install bundler-audit` |
| go | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| cargo | `cargo install cargo-audit` |
| composer | Built-in (`composer audit`) |

The skill will note when tools are missing and continue with available scans.

---

## Limitations

These skills are powerful aids for security review but are **not a replacement for**:

- Professional penetration testing
- Dedicated SAST/DAST tools
- Security-focused code review by experts
- Compliance audits

The skills may produce:
- **False positives**: Patterns that look suspicious but aren't vulnerabilities
- **False negatives**: Vulnerabilities that don't match known patterns
- **Context-limited findings**: Complex business logic vulnerabilities may be missed

Always validate findings and consider engaging security professionals for critical applications.

---

## Security Research Sources

These skills incorporate patterns from:

- [OWASP Top 10:2025](https://owasp.org/Top10/)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- Recent CVEs and security advisories
- Framework-specific security documentation

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Ways to contribute:
- Add patterns for new frameworks
- Improve detection accuracy
- Reduce false positives
- Add new vulnerability patterns
- Improve documentation

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Quick Reference

| Command | What It Does |
|---------|--------------|
| "Run a security audit" | Full multi-agent audit (maximum depth) |
| "Run a quick security scan" | Fast single-pass audit (token-efficient) |
| "Focus on [area]" | Targeted review of specific area |
| "Compare to last audit" | Generate comparison report |
| "Show security history" | Display historical trends |
| "Create remediation plan" | Prioritized fix roadmap |

---

*Built for the Claude Code community*
