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
| [draw-diagram](plugins/development/skills/draw-diagram) | Draw.io (.drawio) 형식의 다이어그램 생성 (AWS 아이콘 지원) |
| [sagemaker-spot-training](plugins/development/skills/sagemaker-spot-training) | SageMaker Spot Training 설정, 리전 선택, 비용 최적화 가이드 |

### Security

보안 리뷰, 취약점 분석, AWS Well-Architected Framework 리뷰

| 스킬 | 설명 |
|------|------|
| [owasp-review](plugins/security/skills/owasp-review) | OWASP Top 10 2025 기반 보안 취약점 검토 |
| [aws-well-architected](plugins/security/skills/aws-well-architected) | AWS Well-Architected Framework 리뷰 오케스트레이터 |
| [aws-wa-operational-excellence](plugins/security/skills/aws-wa-operational-excellence) | 운영 효율성 Pillar 리뷰 |
| [aws-wa-security](plugins/security/skills/aws-wa-security) | 보안 Pillar 리뷰 |
| [aws-wa-reliability](plugins/security/skills/aws-wa-reliability) | 안정성 Pillar 리뷰 |
| [aws-wa-performance](plugins/security/skills/aws-wa-performance) | 성능 효율성 Pillar 리뷰 |
| [aws-wa-cost](plugins/security/skills/aws-wa-cost) | 비용 최적화 Pillar 리뷰 |
| [aws-wa-sustainability](plugins/security/skills/aws-wa-sustainability) | 지속 가능성 Pillar 리뷰 |

### Workflow

Git 워크플로우 및 협업 관련

| 스킬 | 설명 |
|------|------|
| [git-workflow](plugins/workflow/skills/git-workflow) | Git 브랜치 전략 및 커밋 컨벤션 가이드 |
| [tidd](plugins/workflow/skills/tidd) | TiDD(Ticket Driven Development) - No Ticket, No Commit 원칙 강제 훅 |
| [intent-engineering](plugins/workflow/skills/intent-engineering) | Intent Document(INTENT.md) 생성 및 관리 - Why/What/Not/Learnings 기반 프로젝트 의도 문서화 |
| [serverless-migration-advisor](plugins/workflow/skills/serverless-migration-advisor) | AWS always-on 아키텍처를 서버리스+Spot 패턴으로 이행하는 업스트림 어드바이저. 트레이드오프 평가·리스크 플래깅·단계별 이행 계획 생성 후 구현 스킬(sagemaker-spot-training 등)로 위임. |

### Documentation

한국어 기술 문서 작성 및 Q&A 기록

| 스킬 | 설명 |
|------|------|
| [korean-docs](plugins/documentation/skills/korean-docs) | 전문적인 한국어 기술 문서 작성 |
| [qa](plugins/documentation/skills/qa) | 기술/수학적 개념 Q&A 기록 |
| [qa-list](plugins/documentation/skills/qa-list) | 저장된 Q&A 문서 목록 표시 |
| [qa-merge](plugins/documentation/skills/qa-merge) | Q&A 문서를 통합 레퍼런스로 병합 |

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

- "이 코드 보안 검토해줘" → `owasp-review` 스킬 활성화
- "이 코드 리뷰해줘" → `code-review` 스킬 활성화
- "사용자 API 설계해줘" → `api-design` 스킬 활성화
- "이 함수에 대한 테스트 작성해줘" → `test-generator` 스킬 활성화
- "인프라 코드 Well-Architected 리뷰해줘" → `aws-well-architected` 스킬 활성화

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
