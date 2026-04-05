# TiDD 설정 가이드

## .tidd.json 스키마

프로젝트 루트에 `.tidd.json`을 생성하여 TiDD 훅의 동작을 커스터마이즈할 수 있습니다.

### 전체 스키마

```json
{
  "patterns": ["<정규식>", ...],
  "branchPatterns": ["<정규식>", ...],
  "exemptBranches": ["<브랜치명 또는 glob>", ...],
  "exemptTypes": ["<커밋 타입>", ...]
}
```

### 필드 설명

#### `patterns` (선택)

커밋 메시지와 브랜치명에서 검사할 티켓 패턴 목록입니다.

- 기본값: `["#[0-9]+", "[A-Z][A-Z0-9]+-[0-9]+"]`
- 패턴 중 하나라도 매칭되면 통과

**예시: Jira만 사용하는 프로젝트**

```json
{
  "patterns": ["[A-Z][A-Z0-9]+-[0-9]+"]
}
```

**예시: 특정 프로젝트 키만 허용**

```json
{
  "patterns": ["(FE|BE|INFRA)-[0-9]+"]
}
```

#### `branchPatterns` (선택)

브랜치명 전용 추가 패턴입니다. `patterns`에 더해 추가로 검사됩니다.

- 기본값: `[]` (patterns만 사용)
- 브랜치명에 특화된 패턴이 필요할 때 사용

```json
{
  "branchPatterns": ["issue-[0-9]+", "ticket-[0-9]+"]
}
```

#### `exemptBranches` (선택)

티켓 번호 검사를 건너뛸 브랜치 목록입니다. glob 패턴을 지원합니다.

- 기본값: `["main", "master", "develop"]`
- 릴리즈 브랜치나 핫픽스 브랜치 등을 예외로 설정

```json
{
  "exemptBranches": ["main", "master", "develop", "release/*", "hotfix/*"]
}
```

#### `exemptTypes` (선택)

검사를 건너뛸 커밋 타입입니다. 커밋 메시지의 첫 단어 또는 `git merge`/`git revert` 자동 생성 메시지를 기준으로 판단합니다.

- 기본값: `["merge", "revert"]`

```json
{
  "exemptTypes": ["merge", "revert", "chore"]
}
```

## 티켓 시스템별 권장 설정

### GitHub Issues

```json
{
  "patterns": ["#[0-9]+", "GH-[0-9]+"]
}
```

### GitLab Issues

```json
{
  "patterns": ["#[0-9]+", "GL-[0-9]+"]
}
```

### Jira

```json
{
  "patterns": ["[A-Z][A-Z0-9]+-[0-9]+"],
  "branchPatterns": ["[a-z]+-[A-Z][A-Z0-9]+-[0-9]+"]
}
```

### Linear

```json
{
  "patterns": ["[A-Z][A-Z0-9]+-[0-9]+"]
}
```

### Trello (커스텀 접두사)

```json
{
  "patterns": ["TRELLO-[0-9]+", "#[0-9]+"]
}
```

### 복합 환경 (Jira + GitHub Issues)

```json
{
  "patterns": ["#[0-9]+", "[A-Z][A-Z0-9]+-[0-9]+"]
}
```

## Claude Code 훅 설정

### 프로젝트 레벨 (권장)

`.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "command": "<plugin-path>/plugins/workflow/skills/tidd/hooks/validate.sh"
      }
    ]
  }
}
```

### 사용자 레벨 (모든 프로젝트에 적용)

`~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "command": "<plugin-path>/plugins/workflow/skills/tidd/hooks/validate.sh"
      }
    ]
  }
}
```

## 트러블슈팅

### 훅이 동작하지 않을 때

1. 스크립트 실행 권한 확인: `chmod +x validate.sh`
2. 경로가 올바른지 확인: 절대 경로 사용 권장
3. `jq` 또는 `python3`가 설치되어 있는지 확인

### 특정 커밋만 예외 처리하고 싶을 때

`exemptTypes`에 해당 커밋 타입을 추가하거나, `.tidd.json`의 `exemptBranches`를 활용하세요.

### 패턴이 의도대로 매칭되지 않을 때

터미널에서 직접 테스트:

```bash
echo "feat: add feature #123" | grep -E '#[0-9]+|[A-Z][A-Z0-9]+-[0-9]+'
```
