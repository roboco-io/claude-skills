# Claude Code Plugins

Claude Code에서 `/plugin` 명령으로 설치하여 사용할 수 있는 플러그인 모음입니다.
Skills, Commands, Agents, Hooks 등 다양한 플러그인을 제공합니다.

## 플러그인 목록

### Development

코드 리뷰, API 설계, 테스트 생성 등 개발 관련 스킬

| 스킬 | 설명 |
|------|------|
| [code-review](plugins/development/skills/code-review) | 보안, 성능, 유지보수성 관점의 코드 리뷰 |
| [api-design](plugins/development/skills/api-design) | RESTful API 및 GraphQL 스키마 설계 |
| [test-generator](plugins/development/skills/test-generator) | 단위/통합/E2E 테스트 생성 |

### Security

보안 리뷰 및 취약점 분석

| 스킬 | 설명 |
|------|------|
| [security-review](plugins/security/skills/security-review) | OWASP Top 10 2025 기반 보안 취약점 검토 |

### Workflow

Git 워크플로우 및 협업 관련

| 스킬 | 설명 |
|------|------|
| [git-workflow](plugins/workflow/skills/git-workflow) | Git 브랜치 전략 및 커밋 컨벤션 가이드 |

### Documentation

문서 작성 관련

| 스킬 | 설명 |
|------|------|
| [korean-docs](plugins/documentation/skills/korean-docs) | 전문적인 한국어 기술 문서 작성 |

### Memory

세션 간 컨텍스트 영속성 관련

| 플러그인 | 설명 |
|----------|------|
| [ralph-mem](https://github.com/roboco-io/ralph-mem) | Ralph Loop 기반 반복 실행 및 세션 간 컨텍스트 영속성 관리 |

## 설치 방법

### 방법 1: Marketplace 등록 후 설치

```bash
# 1. Marketplace 등록
/plugin marketplace add roboco-io/plugins

# 2. 카테고리별 플러그인 설치
/plugin install development@roboco-plugins
/plugin install security@roboco-plugins
/plugin install workflow@roboco-plugins
/plugin install documentation@roboco-plugins
/plugin install ralph-mem@roboco-plugins
```

### 방법 2: 대화형 UI로 설치

```bash
# 플러그인 매니저 열기
/plugin

# Marketplaces 탭에서 roboco-io/plugins 추가
# Discover 탭에서 원하는 플러그인 선택하여 설치
```

### 방법 3: 로컬 설치 (개발용)

```bash
# 레포지토리 클론
git clone https://github.com/roboco-io/plugins.git

# Claude Code에서 로컬 경로로 marketplace 등록
/plugin marketplace add /path/to/plugins
```

## 스킬 사용법

설치된 스킬은 자동으로 활성화됩니다. 관련 작업을 요청하면 Claude가 해당 스킬을 사용합니다.

**예시:**

- "이 코드 보안 검토해줘" → `security-review` 스킬 활성화
- "이 코드 리뷰해줘" → `code-review` 스킬 활성화
- "사용자 API 설계해줘" → `api-design` 스킬 활성화
- "이 함수에 대한 테스트 작성해줘" → `test-generator` 스킬 활성화

## 플러그인 구조

```
plugins/
└── {category}/                   # development, security, workflow, documentation
    ├── .claude-plugin/
    │   └── plugin.json           # 플러그인 메타데이터
    ├── agents/                   # 에이전트 정의 (선택)
    ├── commands/                 # 커맨드 정의 (선택)
    └── skills/                   # 스킬 정의
        └── {skill-name}/
            ├── SKILL.md          # 스킬 지침
            └── references/       # 참조 파일 (선택)
```

## 새 플러그인 만들기

자세한 내용은 **[플러그인 제작 가이드](docs/plugin-development-guide.md)**를 참고하세요.

## 라이선스

MIT License
