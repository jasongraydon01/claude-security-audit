# Security Audit Skill for Claude Code

A comprehensive, framework-agnostic security audit skill for Claude Code. Run thorough security audits on any codebase with a simple command.

## Overview

This skill enables Claude to perform professional-grade security audits on any codebase. It uses a **discovery-first approach** - detecting your tech stack before applying relevant security patterns, ensuring accurate and relevant findings whether you're running Node.js, Python, Ruby, Go, mobile apps, or anything else.

### Key Features

- **Framework-Agnostic**: Works on any codebase - Node.js, Python, Ruby, Go, Rust, Java, .NET, mobile (React Native, Flutter, Swift, Kotlin), and more
- **Discovery-First**: Automatically detects your tech stack, architecture, and security-relevant configurations
- **Automated Scanning**: Runs deterministic checks for secrets, vulnerable dependencies, and common vulnerabilities
- **Current Threat Intelligence**: Searches for recent CVEs and vulnerabilities specific to your stack
- **AI-Powered Review**: Performs targeted code review based on discovered patterns
- **Persistent History**: Tracks audit results over time for quarter-over-quarter comparison
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

## Installation

### Project-Level (Recommended)

Clone the repository and copy the skill folder to your project:

```bash
git clone https://github.com/jasongraydon01/claude-security-audit.git
mkdir -p your-project/.claude/skills
cp -r claude-security-audit/security-audit your-project/.claude/skills/
```

After installation, your structure should look like:
```
your-project/
└── .claude/
    └── skills/
        └── security-audit/    # <-- The skill folder
            ├── SKILL.md
            ├── references/
            ├── scripts/
            └── templates/
```

### Global Installation

Install globally to use across all projects:

```bash
git clone https://github.com/jasongraydon01/claude-security-audit.git
mkdir -p ~/.claude/skills
cp -r claude-security-audit/security-audit ~/.claude/skills/
```

**Important:** The `security-audit` folder itself must be inside `.claude/skills/`, not just its contents.

## Usage

Once installed, simply ask Claude to run a security audit:

### Basic Audit

```
Run a security audit
```

Claude will:
1. Detect your tech stack
2. Ask grounding questions (first run only)
3. Run automated scans
4. Search for current threats
5. Perform targeted code review
6. Generate a detailed report

### Focused Audits

```
Run a security audit focusing on authentication
```

```
Check for hardcoded secrets
```

```
Audit our API endpoints for authorization issues
```

### Comparison and History

```
Compare this audit to the previous one
```

```
Show our security history
```

```
Generate an executive summary of security findings
```

### Remediation

```
Create a remediation plan for the critical findings
```

## What Gets Created

On first run, the skill creates a `.security-audit/` directory in your project:

```
.security-audit/
├── stack-profile.json      # Detected technology stack
├── project-context.json    # Your answers to grounding questions
├── audit-config.json       # Derived audit configuration
├── audit-history.json      # Historical audit data
├── scan-results/           # Raw scan outputs by date
│   └── 2025-01-06/
│       ├── secrets.json
│       ├── dependencies.json
│       └── ...
└── findings/               # Generated reports
    ├── audit-2025-01-06.md
    └── summary-2025-01-06.md
```

**Note**: Consider adding `.security-audit/` to your `.gitignore` if the findings contain sensitive information.

## Customization

### Adding Stack-Specific Patterns

Create new files in `security-audit/references/stacks/` following the existing format:

```markdown
# FRAMEWORK_NAME.md

## Common Vulnerabilities
...

## Framework-Specific Misconfigurations
...

## Security Features Often Missed
...

## Code Patterns to Review
...
```

### Adjusting Severity

Edit `security-audit/references/SEVERITY_GUIDE.md` to calibrate severity ratings for your organization's risk tolerance.

### Custom Secret Patterns

Add patterns to `security-audit/scripts/secret_scanner.py` in the `SECRET_PATTERNS` dictionary.

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

## Limitations

This skill is a powerful aid for security review but is **not a replacement for**:

- Professional penetration testing
- Dedicated SAST/DAST tools
- Security-focused code review by experts
- Compliance audits

The skill may produce:
- **False positives**: Patterns that look suspicious but aren't vulnerabilities
- **False negatives**: Vulnerabilities that don't match known patterns
- **Context-limited findings**: Complex business logic vulnerabilities may be missed

Always validate findings and consider engaging security professionals for critical applications.

## Security Research Sources

This skill incorporates patterns from:

- [OWASP Top 10:2025](https://owasp.org/Top10/)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- Recent CVEs and security advisories
- Framework-specific security documentation

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Ways to contribute:
- Add patterns for new frameworks
- Improve detection accuracy
- Reduce false positives
- Add new vulnerability patterns
- Improve documentation

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- OWASP for vulnerability categorization and documentation
- The security research community for pattern identification
- Claude Code team for the skills platform

---

## Quick Reference

| Command | What It Does |
|---------|--------------|
| "Run a security audit" | Full audit with all phases |
| "Quick security scan" | Automated scans only |
| "Focus on [area]" | Targeted review of specific area |
| "Compare to last audit" | Generate comparison report |
| "Show security history" | Display historical trends |
| "Create remediation plan" | Prioritized fix roadmap |

---

*Built for the Claude Code community*
