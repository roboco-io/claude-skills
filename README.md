# Claude Skills Collection

Claude Code에서 `/plugin` 명령으로 설치하여 사용할 수 있는 스킬 모음입니다.

## 스킬 목록

| 스킬 | 설명 |
|------|------|
| [security-review](skills/security-review) | OWASP Top 10 2025 기반 보안 취약점 검토 |
| [code-review](skills/code-review) | 보안, 성능, 유지보수성 관점의 코드 리뷰 |
| [api-design](skills/api-design) | RESTful API 및 GraphQL 스키마 설계 |
| [test-generator](skills/test-generator) | 단위/통합/E2E 테스트 생성 |
| [korean-docs](skills/korean-docs) | 전문적인 한국어 기술 문서 작성 |
| [git-workflow](skills/git-workflow) | Git 브랜치 전략 및 커밋 컨벤션 가이드 |

## 설치 방법

### 방법 1: Marketplace 등록 후 설치

```bash
# 1. Marketplace 등록
/plugin marketplace add roboco-io/claude-skills

# 2. 원하는 스킬 설치
/plugin install security-review@roboco-skills
/plugin install code-review@roboco-skills
/plugin install api-design@roboco-skills
/plugin install test-generator@roboco-skills
/plugin install korean-docs@roboco-skills
/plugin install git-workflow@roboco-skills
```

### 방법 2: 대화형 UI로 설치

```bash
# 플러그인 매니저 열기
/plugin

# Marketplaces 탭에서 roboco-io/claude-skills 추가
# Discover 탭에서 원하는 스킬 선택하여 설치
```

### 방법 3: 로컬 설치 (개발용)

```bash
# 레포지토리 클론
git clone https://github.com/roboco-io/claude-skills.git

# Claude Code에서 로컬 경로로 marketplace 등록
/plugin marketplace add /path/to/claude-skills
```

## 스킬 사용법

설치된 스킬은 자동으로 활성화됩니다. 관련 작업을 요청하면 Claude가 해당 스킬을 사용합니다.

**예시:**
- "이 코드 보안 검토해줘" → `security-review` 스킬 활성화
- "이 코드 리뷰해줘" → `code-review` 스킬 활성화
- "사용자 API 설계해줘" → `api-design` 스킬 활성화
- "이 함수에 대한 테스트 작성해줘" → `test-generator` 스킬 활성화

## 새 스킬 만들기

### 1. 스킬 폴더 생성

```bash
mkdir skills/my-new-skill
```

### 2. SKILL.md 작성

`skills/my-new-skill/SKILL.md` 파일을 생성합니다:

```markdown
---
name: my-new-skill
description: 스킬에 대한 설명. Claude가 이 스킬을 언제 사용해야 하는지 명확하게 기술합니다.
---

# 스킬 제목

Claude가 따를 지침을 여기에 작성합니다.

## 섹션 1
...

## 섹션 2
...
```

### 3. 스킬 구조

```
skills/
└── my-new-skill/
    ├── SKILL.md          # 필수: 스킬 정의 파일
    ├── scripts/          # 선택: 실행 가능한 스크립트
    ├── references/       # 선택: 참조 문서
    └── assets/           # 선택: 이미지 등 리소스
```

### SKILL.md 필수 필드

| 필드 | 설명 |
|------|------|
| `name` | 고유 식별자 (소문자, 하이픈 사용) |
| `description` | 스킬의 목적과 사용 시점 설명 |

## 스킬 작성 가이드라인

### 핵심 원칙

1. **간결하게 유지**: context window는 공유 자원입니다
2. **명확한 범위 정의**: 스킬이 언제 활성화되어야 하는지 description에 명시
3. **실용적인 예제 포함**: 추상적인 설명보다 구체적인 예시가 효과적

### 피해야 할 것

- 너무 일반적인 스킬 (모든 상황에 적용되는)
- 과도하게 긴 지침 (context 소모)
- 다른 스킬과 중복되는 기능

## 라이선스

MIT License
