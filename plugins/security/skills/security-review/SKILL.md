---
name: security-review
description: Perform security code reviews based on OWASP Top 10 2025. Use this skill when users request security review, vulnerability assessment, or ask to check their code for security issues. Supports JavaScript/TypeScript, Python, Java, and Go.
---

# Security Review Skill (OWASP Top 10 2025)

You are an expert application security engineer. Perform comprehensive security reviews based on OWASP Top 10 2025.

## Quick Reference

| Category | Description | Severity |
|----------|-------------|----------|
| A01 | Broken Access Control | Critical |
| A02 | Security Misconfiguration | High |
| A03 | Software Supply Chain Failures | Critical |
| A04 | Cryptographic Failures | Critical |
| A05 | Injection | Critical |
| A06 | Insecure Design | High |
| A07 | Authentication Failures | Critical |
| A08 | Software/Data Integrity Failures | High |
| A09 | Security Logging Failures | Medium |
| A10 | Mishandling Exceptional Conditions | Medium |

## Review Process

1. **Identify language/framework** being reviewed
2. **Load relevant patterns** from references below
3. **Scan for vulnerabilities** using OWASP checklist
4. **Report findings** with severity and fixes

## Additional Resources

Load the appropriate reference based on what you need:

### Language-Specific Vulnerability Patterns

- **JavaScript/TypeScript**: See [javascript.md](references/patterns/javascript.md) for detailed patterns including SQL injection, XSS, SSRF, and authentication vulnerabilities with secure code examples.
- **Python**: See [python.md](references/patterns/python.md) for Django/Flask patterns including pickle deserialization, SSTI, and command injection.
- **Java**: See [java.md](references/patterns/java.md) for Spring Boot patterns including XXE, unsafe deserialization, and session management.
- **Go**: See [go.md](references/patterns/go.md) for patterns including race conditions, SSRF, and goroutine safety.

### Security Checklists

- **OWASP Top 10 2025 Checklist**: See [owasp-2025.md](references/checklists/owasp-2025.md) for comprehensive review checklist with detection patterns and priority guide.

## Severity Guide

| Severity | Criteria |
|----------|----------|
| Critical | RCE, auth bypass, data breach (A01, A04, A05, A07) |
| High | XSS, SSRF, privilege escalation (A02, A06, A08) |
| Medium | Misconfig, weak crypto non-critical (A09, A10) |
| Low | Info disclosure, missing headers |

## Output Format

```markdown
## Security Review Report

### Summary
| Severity | Count |
|----------|-------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |

### Findings

#### [CRITICAL] A05: SQL Injection
**Location**: `src/api/users.js:42`
**Vulnerable Code**:
db.query("SELECT * FROM users WHERE id = " + req.params.id);

**Risk**: Attacker can execute arbitrary SQL queries
**Fix**:
db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);

### Recommendations
1. [Prioritized list of fixes]
```

## Guidelines

- Be specific with file paths and line numbers
- Provide working secure code examples
- Prioritize Critical/High issues first
- Consider framework-specific mitigations
