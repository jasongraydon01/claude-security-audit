# Contributing to Security Audit Skill

Thank you for your interest in improving the security-audit skill. This document provides guidelines for contributing.

## Ways to Contribute

### 1. Add Stack-Specific Patterns

Create new files in `security-audit/references/stacks/` for frameworks not yet covered:

```markdown
# STACK_NAME.md

## Overview
Brief description of the stack and its security characteristics.

## Common Vulnerabilities
- Vulnerability 1: Description, detection pattern, remediation
- Vulnerability 2: ...

## Framework-Specific Misconfigurations
- Config issue 1: What to look for, why it's dangerous, how to fix

## Security Features Often Missed
- Feature 1: What it does, how to enable it

## Code Patterns to Review
```language
// Dangerous pattern
vulnerable_code_example()

// Safe alternative
secure_code_example()
```

## References
- Links to official security documentation
- Relevant CVEs
```

### 2. Improve Detection Scripts

Scripts live in `security-audit/scripts/`. Requirements:
- Python 3.8+ compatible
- Standard library only (no pip dependencies)
- Output valid JSON
- Handle missing dependencies gracefully
- Include clear docstrings

### 3. Update Vulnerability Patterns

Keep reference files current with new threats:
- Add new CVEs to relevant stack files
- Update OWASP references when new versions release
- Add emerging attack patterns

### 4. Report False Positives/Negatives

Open an issue with:
- The finding (or missed finding)
- The actual code context
- Why it's a false positive/negative
- Suggested pattern improvement

## Submission Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-stack-patterns`
3. Make your changes
4. Test with a real codebase
5. Submit a pull request with:
   - Description of changes
   - Testing performed
   - Any new dependencies or requirements

## Code Style

### Python Scripts
- Follow PEP 8
- Use type hints where helpful
- Include docstrings for functions
- Handle errors gracefully with informative messages

### Markdown Files
- Use consistent heading hierarchy
- Include code examples with language tags
- Keep lines under 100 characters where practical

## Testing Your Changes

Before submitting:

1. Run the skill on a test codebase
2. Verify JSON output is valid
3. Check that new patterns don't cause false positives on common code
4. Test edge cases (empty files, unusual encodings, etc.)

## Security Considerations

When contributing:
- Never include real credentials or secrets in examples
- Use placeholder patterns like `AKIAIOSFODNN7EXAMPLE`
- Mark example vulnerable code clearly
- Include remediation for every vulnerability pattern

## Questions?

Open an issue with the "question" label for clarification on contribution guidelines.
