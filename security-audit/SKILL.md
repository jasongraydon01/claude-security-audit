---
name: security-audit
description: |
  Performs comprehensive, framework-agnostic security audits on any codebase.
  Discovers the tech stack first, runs automated vulnerability scans, researches
  current threats, and performs targeted code review. Creates persistent audit
  history for tracking improvements over time.

  Use when: running security audits, checking for vulnerabilities, preparing for
  security reviews, comparing security posture over time, or generating security
  reports for stakeholders.
---

# Security Audit Skill

You are performing a comprehensive security audit. Follow these phases in order.

## Important Principles

1. **Discovery over assumption**: Never assume the tech stack. Discover it first.
2. **Run scripts, don't read them**: Execute scripts in `scripts/` and use their JSON output.
3. **Progressive loading**: Only read reference files relevant to the discovered stack.
4. **Persistence**: Save all findings to `.security-audit/` for historical tracking.
5. **Current threats**: Always search for recent vulnerabilities before code review.

---

## Phase 0: Discovery & Grounding

### First-Time Setup

Check if `.security-audit/` directory exists in the project root.

**If it doesn't exist (first audit):**

1. Run the stack discovery script:
   ```bash
   python3 scripts/discover_stack.py
   ```
   This outputs JSON describing: languages, frameworks, architecture type, databases, deployment patterns, and whether AI/LLM components are present.

2. Ask the user these grounding questions:
   - "What does this application do? (brief description)"
   - "What sensitive data does it handle? (PII, payments, health data, auth credentials, or none)"
   - "Are there specific security areas you're concerned about?"
   - "What's your deployment environment? (AWS, GCP, Azure, on-prem, hybrid)"
   - "Is this a greenfield project or does it have legacy components?"

3. Create the `.security-audit/` directory with:
   - `stack-profile.json` - Output from discover_stack.py
   - `project-context.json` - User's answers to grounding questions
   - `audit-config.json` - Derived configuration (which scans to run, which references to load)

### Returning Audit

**If `.security-audit/` exists:**

1. Read `stack-profile.json` and `project-context.json`
2. Check for `findings/` subdirectory
3. If previous audits exist, ask:
   "I found a previous audit from [date]. Should I compare against it, or start fresh?"
4. Re-run `discover_stack.py` to detect any stack changes since last audit

---

## Phase 1: Automated Scanning

Run these scripts based on the discovered stack. All scripts output JSON.

### Always Run

1. **Secret Scanner**
   ```bash
   python3 scripts/secret_scanner.py
   ```
   Detects: API keys, tokens, passwords, connection strings, private keys.

2. **Dependency Audit**
   ```bash
   bash scripts/dependency_audit.sh
   ```
   Checks for known vulnerable packages using the appropriate package manager.

### Run Based on Stack

3. **Auth Finder** (for web applications)
   ```bash
   python3 scripts/auth_finder.py
   ```
   Identifies unprotected routes and endpoints missing authentication.

4. **Input Flow Tracer** (for apps with user input)
   ```bash
   python3 scripts/input_flow_tracer.py
   ```
   Traces user input from entry points to usage, flagging unsanitized paths.

### Save Results

Save all scan outputs to `.security-audit/scan-results/[YYYY-MM-DD]/`

---

## Phase 2: Threat Intelligence Update

Before code review, search for current threats relevant to the discovered stack.

### Required Searches

1. Search for recent framework vulnerabilities:
   - "[primary framework] security vulnerabilities [current year]"
   - "[primary language] CVE [current year]"

2. Search for supply chain risks:
   - "Supply chain attacks [package ecosystem] [current year]"

3. Search for emerging attack patterns:
   - "New web application attack techniques [current year]"

### Conditional Searches

- If AI/LLM components detected:
  - "LLM prompt injection vulnerabilities [current year]"
  - "AI agent security risks [current year]"

- If mobile app detected:
  - "[iOS/Android] app security bypasses [current year]"

### Use Findings

Note any relevant vulnerabilities discovered. Look for these patterns specifically during the targeted code review phase.

---

## Phase 3: Targeted Code Review

Load relevant reference files based on the discovered stack, then review code systematically.

### Load References

Based on `stack-profile.json`, read the appropriate files from `references/`:

**Always load:**
- `references/OWASP_TOP_10.md` - Universal vulnerability patterns
- `references/SEVERITY_GUIDE.md` - Calibration for severity ratings

**Load based on stack:**
- For web apps: `references/AUTH_PATTERNS.md`, `references/INPUT_VALIDATION.md`
- For specific frameworks: `references/stacks/[STACK].md`
- For AI/LLM components: `references/AI_LLM_SECURITY.md`
- For infrastructure: `references/INFRASTRUCTURE.md`
- For databases: `references/stacks/DATABASES.md`

### Review Priority Order

Review code in this priority order:

#### 1. Critical Paths (Always Review)
- **Authentication flows**: Login, logout, password reset, session creation
- **Authorization checks**: Permission verification, role enforcement, access control
- **Cryptographic operations**: Hashing, encryption, key generation, token creation
- **Secret handling**: How credentials and API keys are loaded, stored, transmitted

#### 2. Data-Sensitivity Paths (Based on User Context)
If user indicated sensitive data handling:
- **PII handling**: How personal data is collected, stored, transmitted, deleted
- **Payment flows**: Card handling, transaction processing, PCI compliance
- **Health data**: HIPAA-relevant data flows
- **User content**: Upload handling, content storage, access control

#### 3. Stack-Specific Risks
Using the loaded stack reference file, check for:
- Framework-specific misconfigurations
- Known dangerous patterns for this stack
- Security features that should be enabled but aren't

#### 4. Input/Output Boundaries
- All user input entry points (forms, APIs, file uploads)
- External API integrations
- Database query construction
- Shell command execution
- File system operations
- Serialization/deserialization

#### 5. AI/LLM Components (If Detected)
Using `references/AI_LLM_SECURITY.md`:
- Prompt construction (injection risks)
- Model output handling (validation, sanitization)
- API key management for AI services
- Multi-tenant isolation in AI features

---

## Phase 4: Report Generation

Generate structured findings using the templates.

### Severity Classification

Use `references/SEVERITY_GUIDE.md` for calibration:

- **CRITICAL**: Actively exploitable, high impact, requires immediate fix
- **HIGH**: Exploitable with moderate effort, significant impact, fix before production
- **MEDIUM**: Defense-in-depth issue, moderate impact, address in next sprint
- **LOW**: Best practice improvement, minimal impact, track for future
- **STRENGTHS**: Document what's done well to reinforce good patterns

### Finding Format

For each finding, include:
1. **Location**: File path and line numbers
2. **Title**: Brief description of the issue
3. **Severity**: CRITICAL/HIGH/MEDIUM/LOW
4. **Description**: What the vulnerability is
5. **Impact**: What could happen if exploited
6. **Evidence**: Code snippet demonstrating the issue
7. **Remediation**: Specific fix with code example
8. **References**: CWE, OWASP category, or CVE if applicable

### Generate Reports

1. **Main Audit Report**
   Use `templates/AUDIT_REPORT.md` structure.
   Save to: `.security-audit/findings/audit-[YYYY-MM-DD].md`

2. **Executive Summary**
   Use `templates/EXECUTIVE_SUMMARY.md` structure.
   - Overall risk posture (Critical/High/Medium/Low)
   - Key statistics (counts by severity)
   - Top 3 priorities to address
   Save to: `.security-audit/findings/summary-[YYYY-MM-DD].md`

3. **Comparison Report** (if previous audit exists)
   Use `templates/COMPARISON_REPORT.md` structure.
   - New findings (not in previous)
   - Resolved findings (in previous, not current)
   - Persistent findings (still present)
   - Regression findings (were fixed, now returned)

4. **Update History**
   Append to `.security-audit/audit-history.json`:
   ```json
   {
     "date": "YYYY-MM-DD",
     "critical": N,
     "high": N,
     "medium": N,
     "low": N,
     "strengths": N
   }
   ```

### Present Results

After generating reports:
1. Summarize key findings to the user
2. Highlight the top 3 most important issues to address
3. Offer to generate a remediation plan using `templates/REMEDIATION_PLAN.md`
4. If comparing to previous audit, highlight improvements and regressions

---

## Handling Edge Cases

### Missing Tools
If a required tool isn't available (npm, pip, etc.):
- Note it in the findings
- Skip that specific scan
- Don't fail the entire audit

### Empty or New Projects
If the project has minimal code:
- Focus on configuration review
- Check dependency setup
- Review any authentication scaffolding
- Note that a full audit should be repeated once more code exists

### Monorepos
If multiple projects detected:
- Ask user which project(s) to audit
- Run discovery separately for each
- Generate separate reports or a combined report based on preference

### Unknown Framework
If the framework isn't recognized:
- Use generic patterns from `OWASP_TOP_10.md`
- Focus on universal vulnerabilities
- Note specific patterns that should be added to stack references

---

## User Commands

Respond to these variations:

- "Run a security audit" - Full audit (all phases)
- "Run a quick security scan" - Phase 1 only (automated scans)
- "Focus on authentication security" - Phases 0-1, then targeted auth review
- "Compare to last audit" - Load previous, run current, generate comparison
- "Generate executive summary" - If audit exists, generate summary only
- "Show security history" - Display audit-history.json trends
- "Create remediation plan" - Generate prioritized fix roadmap from findings
