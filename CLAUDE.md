# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

Claude Code 플러그인 마켓플레이스 레포지토리. Skills, Commands, Agents, Hooks를 제공합니다.

- **GitHub**: `roboco-io/plugins`
- **Marketplace 이름**: `roboco-plugins`

## Architecture

```text
.claude-plugin/
└── marketplace.json              # Marketplace 정의 (필수)

plugins/
└── {category}/                   # development, security, workflow, documentation
    ├── .claude-plugin/
    │   └── plugin.json           # 플러그인 메타데이터
    ├── agents/                   # 에이전트 정의 (선택)
    ├── commands/                 # 커맨드 정의 (선택)
    └── skills/                   # 스킬 정의
        └── {skill-name}/
            ├── SKILL.md          # 스킬 지침 (YAML frontmatter + Markdown)
            └── references/       # Progressive disclosure용 참조 파일 (선택)
```

## Plugin Development

### 새 플러그인 추가 시 필수 작업

1. `plugins/{category}/.claude-plugin/plugin.json` 생성
2. `plugins/{category}/skills/{name}/SKILL.md` 생성 (YAML frontmatter 포함)
3. `.claude-plugin/marketplace.json`의 `plugins` 배열에 추가

### marketplace.json 스키마

```json
{
  "name": "roboco-plugins",
  "owner": { "name": "roboco-io" },
  "plugins": [
    {
      "name": "category-name",
      "source": "./plugins/category-name",
      "category": "category",
      "skills": ["./plugins/category-name/skills/skill-name/SKILL.md"]
    }
  ]
}
```

**주의**: `plugins` 배열 항목은 문자열이 아닌 객체여야 함.

### SKILL.md 구조

```markdown
---
name: skill-name
description: 스킬 설명. Claude가 언제 이 스킬을 사용해야 하는지 명시.
---

# 스킬 제목

[지침 내용]
```

### Progressive Disclosure

SKILL.md는 500줄 이하로 유지하고, 상세 내용은 `references/` 디렉토리에 분리:

- SKILL.md에서 `[file.md](references/file.md)` 형식으로 참조
- Claude가 필요할 때만 참조 파일을 로드함

## Testing

```bash
# 로컬에서 marketplace 등록
/plugin marketplace add /path/to/plugins

# 플러그인 설치
/plugin install development@roboco-plugins

# 검증
/plugin validate .
```

## Troubleshooting

- **origin/HEAD 오류**: `git remote set-head origin -a` 실행
- **Invalid schema 오류**: marketplace.json에 `owner.name` 필드 확인
- **플러그인 미활성화**: SKILL.md의 `name`과 plugin.json의 `name` 일치 여부 확인
