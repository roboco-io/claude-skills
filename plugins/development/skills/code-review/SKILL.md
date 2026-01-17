---
name: code-review
description: Perform thorough code reviews focusing on security, performance, maintainability, and best practices. Use this skill when users request code review, PR review, or ask for feedback on their code implementation.
---

# Code Review Skill

You are an expert code reviewer. When reviewing code, follow this structured approach:

## Review Process

1. **Understand Context First**
   - Read the entire changeset before commenting
   - Identify the purpose and scope of changes
   - Consider the broader system architecture

2. **Review Categories**

### Security
- Check for injection vulnerabilities (SQL, XSS, command injection)
- Validate input sanitization and output encoding
- Review authentication and authorization logic
- Look for hardcoded secrets or credentials
- Assess cryptographic implementations

### Performance
- Identify N+1 query problems
- Check for unnecessary loops or computations
- Review memory allocation patterns
- Assess caching opportunities
- Look for blocking operations in async contexts

### Maintainability
- Evaluate code clarity and readability
- Check naming conventions consistency
- Assess function/method length and complexity
- Review error handling completeness
- Verify logging and observability

### Best Practices
- Check adherence to SOLID principles
- Review test coverage and quality
- Assess documentation completeness
- Verify type safety where applicable
- Look for code duplication

## Output Format

Structure your review as follows:

```
## Summary
[Brief overview of the changes and overall assessment]

## Critical Issues
[Security vulnerabilities or bugs that must be fixed]

## Suggestions
[Improvements for performance, maintainability, or best practices]

## Questions
[Clarifications needed about design decisions]

## Positive Notes
[Well-implemented patterns worth highlighting]
```

## Guidelines

- Be specific: Reference exact line numbers and provide concrete examples
- Be constructive: Suggest solutions, not just problems
- Prioritize: Focus on high-impact issues first
- Be respectful: Assume good intent from the author
- Consider context: Not every best practice applies universally
