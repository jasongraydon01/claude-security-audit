# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-06

### Added
- Initial release of the security-audit skill
- Framework-agnostic architecture discovery (`discover_stack.py`)
- Automated secret scanning (`secret_scanner.py`)
- Dependency vulnerability auditing (`dependency_audit.sh`)
- Authentication endpoint discovery (`auth_finder.py`)
- Input flow tracing (`input_flow_tracer.py`)
- Codebase context generation (`generate_context.py`)
- OWASP Top 10:2025 reference documentation
- Stack-specific security patterns for:
  - JavaScript/TypeScript (Node, Next.js, React, Vue, Angular)
  - Python (Django, Flask, FastAPI)
  - Ruby (Rails, Sinatra)
  - Go web frameworks
  - Java (Spring, Jakarta)
  - .NET (ASP.NET Core)
  - Mobile (React Native, Flutter, iOS, Android)
  - Databases (SQL, NoSQL)
  - Infrastructure (Docker, Kubernetes, IaC)
- AI/LLM security patterns for prompt injection and API security
- Audit history tracking and comparison reports
- Executive summary generation
- Remediation planning templates

### Security Research Sources
- OWASP Top 10:2025 vulnerability categories
- Recent CVEs including React2Shell (CVE-2025-55182)
- LangChain vulnerability (CVE-2025-68664)
- Mobile security threats (LANDFALL spyware)
- LLM prompt injection patterns
