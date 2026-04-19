# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **serverless-migration-advisor** (workflow): AWS always-on 아키텍처를 서버리스+Spot 패턴으로 이행할 때 사용하는 업스트림 어드바이저. 5-Phase 인터뷰 → 타겟 아키텍처 매핑 → 단계별 체크리스트 리포트 생성. AWS Docs 인용 의무 + serverless-autoresearch($3.94/48실험) 및 serverless-openclaw($1/월) 검증 사례 인용. 구현 how-to는 `sagemaker-spot-training` 등으로 위임. (#3)
- development 플러그인에 `sagemaker-spot-training` 스킬 등록 (marketplace.json + plugins/development/README.md). `serverless-migration-advisor`의 Delegation 타겟으로 참조되는 스킬을 실제 설치 가능 상태로 전환. (#5)
- **llm-wiki** (documentation): Karpathy LLM Wiki 패턴 구현 스킬. 8개 서브커맨드(init/ingest/query/lint/sync/export/qmd-index/lancedb-sync). qmd 설치 시 하이브리드 검색 자동 활성, 미설치 시 INDEX.md 라우팅으로 graceful degrade. LanceDB + Embedding Atlas 선택적 벡터 인덱스 지원. Obsidian 호환 `[[wiki-link]]`. 워크스페이스 CLAUDE.md "LLM Wiki 활용 규칙"과 통합. (#8)

### Changed

- workflow 플러그인의 `intent-engineering` 스킬 디렉토리와 marketplace 경로를 `intent`로 통일 (frontmatter `name: intent`와 일치). (#4)

## [0.2.0-beta] - 2026-04-07

### Added

- `intent-engineering` 스킬 — INTENT.md 기반 프로젝트 의도 문서화 및 생명주기 관리
- AWS Well-Architected 6개 Pillar별 references 파일 추가
- CHANGELOG.md 도입
- LICENSE (MIT) 추가
- `.gitignore` 추가

### Changed

- GitHub Actions CI: Node.js 20 → 24 업그레이드
- 전체 테스트 인프라 git 추적에 포함 (vitest.config.ts, 테스트 파일, helpers)

## [0.1.0-alpha] - 2026-04-05

### Added

- **Development** 플러그인
  - `code-review` — 보안, 성능, 유지보수성 관점의 코드 리뷰
  - `api-design` — RESTful API 및 GraphQL 스키마 설계
  - `test-generator` — 단위/통합/E2E 테스트 생성
  - `draw-diagram` — Draw.io 형식 다이어그램 생성 (AWS 아이콘 지원)
  - `sagemaker-spot-training` — SageMaker Spot Training 설정 및 비용 최적화
- **Security** 플러그인
  - `owasp-review` — OWASP Top 10 2025 기반 보안 취약점 검토
  - `aws-well-architected` — AWS Well-Architected Framework 통합 리뷰 오케스트레이터
  - 6개 Pillar별 하위 스킬 (Operational Excellence, Security, Reliability, Performance, Cost, Sustainability)
- **Workflow** 플러그인
  - `git-workflow` — Git 브랜치 전략 및 커밋 컨벤션 가이드
  - `tidd` — TiDD(Ticket Driven Development) "No Ticket, No Commit" 강제 훅
- **Documentation** 플러그인
  - `korean-docs` — 한국어 기술 문서 작성
  - `qa` / `qa-list` / `qa-merge` — Q&A 기록 및 통합 관리
- **Memory** 플러그인 (외부)
  - `ralph-mem` v0.1.10 — Ralph Loop 기반 세션 간 컨텍스트 영속성 관리
- GitHub Actions CI (vitest 자동 실행)
- TiDD 훅 자동화 테스트 (27개)

[Unreleased]: https://github.com/roboco-io/plugins/compare/v0.2.0-beta...HEAD
[0.2.0-beta]: https://github.com/roboco-io/plugins/compare/v0.1.0-alpha...v0.2.0-beta
[0.1.0-alpha]: https://github.com/roboco-io/plugins/releases/tag/v0.1.0-alpha
