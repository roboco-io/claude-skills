---
name: llm-wiki
description: Karpathy LLM Wiki 패턴 구현. 프로젝트 문서(스펙/ADR/회의록)를 wiki/raw/에 모으고 LLM이 컴파일하여 wiki/에 교차참조 마크다운 위키를 생성·갱신. qmd 설치 시 하이브리드 검색 자동 활성, 미설치 시 INDEX.md 라우팅으로 graceful degrade. LanceDB 선택적 벡터 인덱스. Obsidian 호환. 하위 명령 - init, ingest, query, lint, sync, export, qmd-index, lancedb-sync.
argument-hint: "[init|ingest|query|lint|sync|export|qmd-index|lancedb-sync] [args]"
---

# llm-wiki — 프로젝트 컨텍스트 위키

> 참고: [Karpathy LLM Wiki](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f).
> **검색이 아닌 컴파일**이 핵심 — 한 번 이해한 것은 계속 다듬어 재활용한다.

## 언제 사용하나

트리거: "위키 초기화", "wiki 초기화", "wiki ingest", "문서 wiki로 정리", "프로젝트 컨텍스트 위키", "llm wiki", "knowledge base 구축", "wiki query", "서드파티 소스 컴파일".

이 스킬은 워크스페이스 CLAUDE.md의 **"LLM Wiki 활용 규칙"을 실제 실행 가능하게** 한다.

## 디렉토리 구조

프로젝트 루트에 `init` 명령으로 생성되는 구조:

```text
wiki/
├── index.md              # 자동 재빌드 (수동 편집 금지)
├── log.md                # ingest 이력
├── raw/                  # 원본 소스 드롭존 (불변)
│   └── YYYY-MM-DD_{source}.md
├── {page}.md             # 컴파일된 위키 페이지 ([[wiki-link]] 교차참조)
├── .gitignore            # raw/private/, .lancedb/ 기본 제외
└── .lancedb/             # 선택적 벡터 인덱스 (lancedb-sync 시)
```

프로젝트 루트 `CLAUDE.md`에는 "LLM Wiki 활용 규칙" 블록이 `init` 시 자동 추가된다.

## 페이지 프론트매터 규약

```yaml
---
title: "Rate Limiter Design"
type: decision          # concept | decision | entity | meeting | policy | comparison
tags: [api, reliability]
status: active          # draft | active | stale | archived
confidence: high        # high | medium | low | tentative
created: 2026-04-19
updated: 2026-04-19
sources: [raw/2026-04-18_arch-review.md]
---
```

상세는 [page-templates.md](references/page-templates.md) 참조.

## 8개 명령

### `init` — 구조 초기화

**실행**: `scripts/init.sh [project-root]`

- `wiki/` 디렉토리 구조 생성 (`raw/` 포함)
- `wiki/index.md`, `log.md`, `.gitignore` 초기 파일
- 프로젝트 루트 `CLAUDE.md`에 LLM Wiki 블록 추가 ([claude-md-block.md](references/claude-md-block.md))
- qmd / LanceDB 환경 감지 및 설치 안내

### `ingest <source>` — 소스 컴파일

**실행**: LLM 주도 워크플로 (스크립트 없음)

상세 5단계: [ingest-workflow.md](references/ingest-workflow.md)

1. 소스 읽기 (`raw/`에 드롭된 파일 또는 인자 경로)
2. 엔티티·개념 추출
3. 기존 wiki 페이지와 교차 참조 검토
4. 페이지 생성/갱신 (10-15 페이지)
5. `log.md`에 기록

페이지 유형 선택은 [page-templates.md](references/page-templates.md) 6종(concept/decision/entity/meeting/policy/comparison) 참조.

### `query <질문>` — 위키 검색

**qmd 감지 시 (하이브리드 검색)**:
1. `qmd query "<질문>"` 호출
2. BM25 + 벡터 + LLM 재순위 결과 top-10
3. LLM이 컨텍스트 트리 + 매칭 페이지로 답변 합성
4. 답변에 `[[wiki-link]]`로 출처 인용

**qmd 미감지 시 (graceful degrade — INDEX.md 라우팅)**:
1. `wiki/index.md` 읽어 관련 페이지 후보 3-5개 식별
2. 후보 페이지 본문 로드 + `[[link]]` 2-hop 확장
3. LLM이 로드된 컨텍스트로 답변
4. "qmd 미설치 — 하이브리드 검색 원하면 `brew install qmd`" 안내 첨부

qmd 설정·MCP 연동: [qmd-integration.md](references/qmd-integration.md).

### `lint` — 건강 점검

**실행**: `scripts/lint_wiki.py [--wiki-dir PATH]`

검사 항목:
- 끊어진 `[[wiki-link]]`
- 고아 페이지 (어디에서도 참조되지 않음)
- frontmatter 필수 필드 누락 (`title`, `updated`)
- `confidence: low` 또는 `tentative` 페이지 플래그

Exit code: 0 = clean, 1 = issues found.

### `sync` — index.md 재빌드

**실행**: `scripts/sync_index.py [--wiki-dir PATH]`

`wiki/*.md` 스캔 → frontmatter `type` 별로 그룹화 → `index.md` 재생성. 수동 편집은 덮어씌워지므로 index에는 내용을 쓰지 말 것.

### `export <template>` — 템플릿 출력

**실행**: LLM 주도 워크플로

지원 템플릿:
- `onboarding` — 신규 팀원 온보딩 가이드
- `adr-summary` — decision 유형 페이지 목록 + 요약
- `release-notes` — 지정 기간의 변경 페이지 요약
- `qa-export` — 축적된 지식을 별도 Q&A 문서로

### `qmd-index` — qmd 인덱스 (선택)

**실행**: `scripts/qmd_index.sh [wiki-dir]`

qmd 설치 전제. 없으면 설치 안내 후 exit 1:
- macOS: `brew install qmd`
- 기타: `npm install -g @tobilu/qmd`

내부적으로 `qmd index wiki/` + `qmd context add` 실행. Claude Code MCP 통합은 [qmd-integration.md](references/qmd-integration.md).

### `lancedb-sync` — LanceDB 벡터 인덱스 (선택)

**실행**: `scripts/lancedb_sync.py [--wiki-dir PATH] [--model MODEL]`

Phase 3 옵션. `pip install lancedb duckdb sentence-transformers` 전제. 없으면 설치 안내 후 exit 1.

상세·SQL 쿼리 예·Embedding Atlas 연결: [lancedb-integration.md](references/lancedb-integration.md).

## Graceful Degrade 원칙

- `query`는 항상 작동 (qmd 있으면 하이브리드, 없으면 INDEX.md 라우팅으로 degrade)
- 명시 명령(`qmd-index`, `lancedb-sync`)은 의존성 없으면 설치 안내 + exit 1
- `init`은 환경 감지만 할 뿐 종료 코드에 영향 없음

## 통합 포인트

### 다른 스킬과의 관계

- **`qa-merge`**: Q&A 카드 통합 결과를 `wiki/raw/`에 드롭 → 자동 ingest 대상. Q&A 축적 → 위키 컴파일 파이프라인.
- **`intent`**: `INTENT.md` 변경 시 `wiki/raw/`로 복사 후 ingest → Why/What/Not/Learnings가 decision·entity 페이지로 분해.
- **`korean-docs`**: 한국어 출력 규칙과 직교. 위키 페이지 식별자는 영어 허용 (Obsidian 호환).

### Obsidian

`wiki/`를 Obsidian vault로 열면:
- 그래프 뷰로 교차 참조 시각화
- `[[wiki-link]]` 네이티브 네비게이션
- 마크다운 실시간 프리뷰
- 백링크 자동 추적

## Karpathy 원칙 준수

- `raw/`는 LLM이 수정하지 않음 (read-only for wiki purposes)
- `wiki/*.md`는 LLM이 증분 갱신 (컴파일)
- CLAUDE.md가 스키마·컨벤션을 정의
- 3가지 연산(Ingest/Query/Lint)이 핵심, 나머지는 보조

원본 설계 결정 기록: [karpathy-pattern.md](references/karpathy-pattern.md).

## References (Progressive Disclosure)

- [page-templates.md](references/page-templates.md) — 6개 페이지 유형 템플릿
- [ingest-workflow.md](references/ingest-workflow.md) — Ingest 5단계 상세
- [claude-md-block.md](references/claude-md-block.md) — CLAUDE.md 추가 블록 템플릿
- [qmd-integration.md](references/qmd-integration.md) — qmd 설치·설정·MCP
- [lancedb-integration.md](references/lancedb-integration.md) — LanceDB + Embedding Atlas (Phase 3)
- [karpathy-pattern.md](references/karpathy-pattern.md) — 원본 패턴 + 본 구현 결정 기록

## Anti-patterns

- `wiki/index.md` 수동 편집 (sync에 덮어씌워짐 — 내용은 페이지에)
- `wiki/raw/`의 원본 수정 (불변 원칙 위반 — 새 버전을 새 파일로 드롭)
- 페이지 제목에 한국어 공백 (Obsidian `[[link]]` 호환성 저하 — slug는 영어/하이픈 권장)
- 모순되는 정보를 두 페이지에 분산 (합성하여 단일 페이지로 정리하는 것이 위키의 목적)
- `lint` 미실행 상태로 장기 방치 (고아·끊어진 링크 누적)
- 벡터 DB 과잉 도입 (500페이지 미만은 qmd만으로 충분)
