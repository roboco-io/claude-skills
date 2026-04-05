---
name: tidd
description: "TiDD(Ticket Driven Development) 설정 및 관리. 'No Ticket, No Commit' 원칙을 강제하는 PreToolUse 훅을 설치하고, 티켓 패턴·예외 규칙을 구성할 때 사용. 'TiDD 설정', '티켓 기반 개발', 'No Ticket No Commit' 키워드로 트리거."
---

# TiDD — Ticket Driven Development

**No Ticket, No Commit.** 모든 코드 변경은 반드시 추적 가능한 티켓과 연결되어야 합니다.

## 원칙

1. **모든 변경에는 티켓이 있어야 한다** — 티켓 없이 코드를 변경하지 않는다
2. **커밋 메시지 또는 브랜치명에 티켓 번호가 포함되어야 한다** — 둘 중 하나만 만족하면 통과
3. **티켓은 변경의 맥락(Why)을 담는다** — 코드는 What, 티켓은 Why

## 지원 티켓 시스템

| 시스템 | 패턴 예시 | 정규식 |
|--------|-----------|--------|
| GitHub Issues | `#123`, `org/repo#456` | `#[0-9]+` |
| GitLab Issues | `#123`, `group/project#456` | `#[0-9]+` |
| Jira | `PROJ-123`, `DEV-456` | `[A-Z][A-Z0-9]+-[0-9]+` |
| Linear | `ENG-123`, `FE-456` | `[A-Z][A-Z0-9]+-[0-9]+` |
| Trello | `TRELLO-123` | `[A-Z][A-Z0-9]+-[0-9]+` |

기본 패턴: `#[0-9]+` 또는 `[A-Z][A-Z0-9]+-[0-9]+`

## 설치

### 1. 훅 스크립트 권한 설정

```bash
chmod +x plugins/workflow/skills/tidd/hooks/validate.sh
```

### 2. Claude Code 설정에 훅 등록

프로젝트의 `.claude/settings.json`에 추가:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "command": "/path/to/plugins/workflow/skills/tidd/hooks/validate.sh"
      }
    ]
  }
}
```

> **팁**: 절대 경로 대신 플러그인 설치 경로 기준으로 설정하세요.

### 3. (선택) 프로젝트 커스터마이즈

프로젝트 루트에 `.tidd.json` 생성:

```json
{
  "patterns": ["#[0-9]+", "[A-Z][A-Z0-9]+-[0-9]+"],
  "branchPatterns": ["[A-Z][A-Z0-9]+-[0-9]+", "issue-[0-9]+"],
  "exemptBranches": ["main", "master", "develop", "release/*", "hotfix/*"],
  "exemptTypes": ["merge", "revert"]
}
```

설정 상세는 [configuration.md](references/configuration.md)를 참조하세요.

## 동작 방식

```
git commit 감지
    │
    ├─ merge/revert 커밋? ──→ 통과
    │
    ├─ exempt 브랜치? ──→ 통과
    │
    ├─ 커밋 메시지에 티켓 번호? ──→ 통과
    │
    ├─ 브랜치명에 티켓 번호? ──→ 통과
    │
    └─ 차단: "No Ticket, No Commit!"
```

## 커밋 메시지 예시

```bash
# GitHub Issues
git commit -m "feat(auth): add OAuth2 support #123"

# Jira
git commit -m "feat(auth): add OAuth2 support PROJ-123"

# 본문에 포함해도 OK
git commit -m "feat(auth): add OAuth2 support

Resolves #123"
```

## 브랜치명 예시

```bash
# 브랜치명에 티켓 번호가 있으면 커밋 메시지에는 없어도 통과
git checkout -b feature/PROJ-123-oauth-login
git commit -m "feat(auth): add OAuth2 support"  # 통과!
```
