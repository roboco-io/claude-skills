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

### 스킬 간 호출 관계

`aws-well-architected` 스킬은 오케스트레이터로서 6개 Pillar별 하위 스킬(`aws-wa-*`)을 호출하고 통합 리포트를 생성함. 이처럼 스킬이 다른 스킬을 호출하는 패턴이 존재하므로, 오케스트레이터 스킬 수정 시 하위 스킬의 인터페이스(입출력 형식)가 유지되는지 확인 필요.

## Plugin Development

### 새 플러그인 추가 시 필수 작업

1. `plugins/{category}/.claude-plugin/plugin.json` 생성
2. `plugins/{category}/skills/{name}/SKILL.md` 생성 (YAML frontmatter 포함)
3. `.claude-plugin/marketplace.json`의 `plugins` 배열에 추가
4. `README.md`의 플러그인 목록 업데이트 (아래 규칙 참조)

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

**주의사항:**
- `plugins` 배열 항목은 문자열이 아닌 객체여야 함
- 로컬 플러그인의 `source`는 문자열 경로, 외부 플러그인의 `source`는 `{ "source": "npm"|"github", ... }` 객체
- `skills` 배열의 경로는 marketplace.json 기준 상대 경로

### 외부 플러그인 추가

npm 또는 GitHub에서 외부 플러그인을 참조할 수 있음:

```json
{
  "name": "external-plugin",
  "source": { "source": "npm", "package": "package-name" },
  "version": "1.0.0",
  "description": "설명",
  "category": "category"
}
```

```json
{
  "name": "external-plugin",
  "source": { "source": "github", "repo": "owner/repo" },
  "version": "1.0.0",
  "description": "설명",
  "category": "category"
}
```

외부 플러그인은 `skills` 배열이 없으며, `source` 객체로 로컬/외부를 구분함.

### plugin.json 스키마

각 카테고리 디렉토리의 `.claude-plugin/plugin.json` 최소 필드:

```json
{
  "name": "category-name",
  "description": "카테고리 설명",
  "version": "1.0.0",
  "category": "category-name"
}
```

`name`은 marketplace.json의 해당 항목 `name`과 일치해야 함.

### SKILL.md 구조

```markdown
---
name: skill-name
description: 스킬 설명. Claude가 언제 이 스킬을 사용해야 하는지 명시.
---

# 스킬 제목

[지침 내용]
```

`description`은 Claude가 스킬 선택에 사용하므로, **트리거 조건을 구체적으로** 기술할 것.

### Progressive Disclosure

SKILL.md는 500줄 이하로 유지하고, 상세 내용은 `references/` 디렉토리에 분리:

- SKILL.md에서 `[file.md](references/file.md)` 형식으로 참조
- Claude가 필요할 때만 참조 파일을 로드함

### README.md 동기화 규칙

플러그인 추가/수정 시 `README.md`의 "플러그인 목록" 섹션을 업데이트:

1. **데이터 소스**: `.claude-plugin/marketplace.json`과 각 `SKILL.md`의 frontmatter
2. **카테고리별 섹션**: marketplace.json의 `category` 필드 기준으로 그룹화
3. **스킬 정보 추출**:
   - `name`: SKILL.md frontmatter의 `name`
   - `description`: SKILL.md frontmatter의 `description` (한국어로 요약)
   - `link`: `plugins/{category}/skills/{skill-name}` 경로
4. **외부 플러그인**: `source`가 객체인 경우 (npm/github) 별도 표기
   - npm: 패키지명 링크
   - github: 레포지토리 링크

**테이블 형식:**

```markdown
### {Category 이름}

{카테고리 설명}

| 스킬 | 설명 |
|------|------|
| [skill-name](plugins/category/skills/skill-name) | 스킬 설명 |
```

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
