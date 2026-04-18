# Workflow 플러그인 (Workflow)

개발의 **의도(Intent) → 프로세스(Ticket) → 실행(Git)** 을 상류에서 하류로 연결하는 메타 워크플로 스킬 모음입니다. 왜 만드는지, 어떤 티켓으로 추적되는지, 어떤 브랜치와 커밋으로 구현되는지를 일관된 규칙으로 관리합니다.

## 특징

- **Git 워크플로 표준화** — `git-workflow`가 브랜치 전략·커밋 컨벤션·PR 관리에 대한 팀 공통 규칙을 안내합니다.
- **티켓 기반 개발(TiDD)** — `tidd`가 "No Ticket, No Commit" 원칙을 PreToolUse 훅으로 강제하여 티켓 번호 없는 커밋을 차단합니다.
- **의도 중심 설계** — `intent`가 INTENT.md로 프로젝트의 Why/What/Not/Learnings를 문서화하고 학습을 통해 의도를 진화시킵니다.
- **서버리스 이행 조언** — `serverless-migration-advisor`가 AWS always-on 아키텍처를 서버리스+Spot 패턴으로 이행할 때 트레이드오프 평가와 단계별 계획을 제공합니다.
- **상류-하류 연결** — 의도(왜) → 티켓(무엇을, 언제) → Git(어떻게) → 아키텍처 이행(무엇으로) 단계를 건너뛰지 않는 규율을 제공합니다.

## 수록 스킬

| 스킬 | 용도 | 트리거 예시 |
|------|------|-------------|
| [git-workflow](skills/git-workflow) | 브랜치 전략·커밋 컨벤션·PR 관리 가이드 | "팀 Git 컨벤션 정리해줘", "커밋 메시지 규칙 잡아줘" |
| [tidd](skills/tidd) | No Ticket, No Commit 훅 설치 및 티켓 패턴 구성 | "TiDD 설정해줘", "티켓 없는 커밋 차단해줘" |
| [intent](skills/intent) | INTENT.md로 프로젝트 의도(Why/What/Not/Learnings) 문서화 | "INTENT.md 작성 도와줘", "프로젝트 방향 잡기" |
| [serverless-migration-advisor](skills/serverless-migration-advisor) | AWS always-on 아키텍처를 서버리스+Spot 패턴으로 이행하는 업스트림 어드바이저 | "EC2에서 Lambda로 이행", "ALB에서 API Gateway", "Spot 이행" |

## 사용 예시

### 예시 1 — 새 프로젝트 시작
`intent`로 INTENT.md를 먼저 작성하여 왜 만드는지·무엇을 만들지·무엇은 만들지 않을지를 합의합니다. 탐구와 학습이 누적되면 Learnings 섹션에 반영하여 의도를 진화시키거나 피벗·종료 판단에 근거로 삼습니다.

### 예시 2 — 티켓 기반 개발 강제
`tidd`를 설치하면 PreToolUse 훅이 커밋 메시지·브랜치명 중 하나에 티켓 번호가 포함되어 있는지 확인하고, 없으면 커밋을 차단합니다. 티켓 패턴과 예외 규칙은 프로젝트별로 설정 가능합니다.

### 예시 3 — 팀 Git 컨벤션 정립
`git-workflow`로 Conventional Commits 기반 커밋 메시지 규칙, 브랜치 네이밍, PR 템플릿 등을 한 번에 정리하여 신규 멤버 온보딩 문서로 활용합니다.

### 예시 4 — 서버리스 이행 계획 수립
`serverless-migration-advisor`로 기존 EC2·ALB·RDS 아키텍처를 Lambda·Fargate Spot·Aurora Serverless v2로 옮길 때 트레이드오프와 리스크를 AWS 공식문서·검증 사례 기반으로 검토하고 단계별 체크리스트 리포트를 생성합니다. 세부 구현은 `sagemaker-spot-training` 등 후속 스킬로 위임합니다.

## 설치

```bash
/plugin marketplace add roboco-io/plugins
/plugin install workflow@roboco-plugins
```

## 요구사항

- `tidd`는 Claude Code의 PreToolUse 훅을 사용하므로 `.claude/settings.json`에 훅 등록 권한이 필요합니다.
- 티켓 번호 패턴은 기본값(`#숫자`, `PROJ-숫자` 등) 외에 프로젝트별로 재정의 가능합니다.

## 관련 문서

- 루트 README: [../../README.md](../../README.md)
- 플러그인 제작 가이드: [../../docs/plugin-development-guide.md](../../docs/plugin-development-guide.md)
