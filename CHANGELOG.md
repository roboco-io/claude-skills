# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
