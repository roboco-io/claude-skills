---
name: git-workflow
description: Guide Git workflows including branching strategies, commit conventions, and PR management. Use this skill when users need help with Git operations, branch management, commit messages, or establishing team Git workflows.
---

# Git Workflow Skill

You are an expert in Git version control and team collaboration workflows.

## Commit Message Convention

### Format
```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types
| Type | Description |
|------|-------------|
| feat | New feature |
| fix | Bug fix |
| docs | Documentation only |
| style | Code style (formatting, semicolons) |
| refactor | Code change that neither fixes nor adds |
| perf | Performance improvement |
| test | Adding or updating tests |
| chore | Build process or auxiliary tools |
| ci | CI configuration changes |

### Examples
```
feat(auth): add OAuth2 login support

Implement Google and GitHub OAuth2 providers.
Users can now link multiple social accounts.

Closes #123
```

```
fix(api): handle null response from payment service

The payment service returns null for cancelled transactions.
Added null check to prevent TypeError.

Fixes #456
```

## Branching Strategies

### GitHub Flow (Recommended for most teams)
```
main (production-ready)
  └── feature/add-login
  └── feature/update-dashboard
  └── fix/payment-bug
```

**Rules:**
- `main` is always deployable
- Create feature branches from `main`
- Open PR when ready for review
- Merge to `main` after approval
- Deploy immediately after merge

### Git Flow (For scheduled releases)
```
main (production)
develop (integration)
  └── feature/add-login
  └── release/v1.2.0
  └── hotfix/critical-bug
```

**Rules:**
- `main` reflects production
- `develop` is integration branch
- Feature branches from `develop`
- Release branches for final prep
- Hotfix branches from `main`

## Branch Naming Convention

```
<type>/<ticket>-<description>

Examples:
feature/AUTH-123-oauth-login
fix/BUG-456-null-pointer
chore/INFRA-789-update-deps
```

## Pull Request Guidelines

### PR Title
Follow commit message format:
```
feat(auth): add OAuth2 login support
```

### PR Description Template
```markdown
## Summary
Brief description of changes

## Changes
- Change 1
- Change 2

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Screenshots (if applicable)

## Related Issues
Closes #123
```

### Review Checklist
- [ ] Code follows project conventions
- [ ] Tests are included and passing
- [ ] Documentation is updated
- [ ] No sensitive data exposed
- [ ] Breaking changes are documented

## Common Operations

### Rebase vs Merge
**Use Rebase:**
- Updating feature branch with main
- Cleaning up local commits before PR
- Linear history preferred

**Use Merge:**
- Merging PR to main
- Preserving branch history
- Team policy requires merge commits

### Interactive Rebase
```bash
# Squash last 3 commits
git rebase -i HEAD~3

# Rebase onto main
git rebase -i main
```

### Undo Operations
```bash
# Undo last commit (keep changes)
git reset --soft HEAD~1

# Undo last commit (discard changes)
git reset --hard HEAD~1

# Revert a pushed commit
git revert <commit-hash>
```

## Best Practices

1. **Commit Often, Push Regularly**
   - Small, atomic commits
   - Push at least daily

2. **Write Meaningful Messages**
   - Explain why, not just what
   - Reference issues/tickets

3. **Keep Branches Short-lived**
   - Merge within days, not weeks
   - Delete branches after merge

4. **Review Before Merging**
   - At least one approval required
   - CI checks must pass
