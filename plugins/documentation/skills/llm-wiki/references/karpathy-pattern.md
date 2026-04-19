> **Snapshot date**: 2026-04-19
> **Source**: https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f
> **Description**: Karpathy 원본 패턴 요약 및 본 구현 결정 기록

# Karpathy LLM Wiki 패턴

## 핵심 아이디어

> RAG는 무상태. Wiki는 복리로 축적된다.

대부분의 LLM 작업은 RAG로 매번 처음부터 지식을 재발견한다. LLM Wiki는 달리, 지속적으로 상호 연결된 지식 베이스를 **증분 구축**한다. 교차 참조가 이미 존재하고, 모순이 이미 플래그되며, 합성 결과가 이전에 수집된 모든 것을 반영한다.

Andrej Karpathy가 2026년 4월 3~4일 X 포스트와 GitHub gist로 발표. 수일 내 5,000+ 스타, 3,600+ 포크.

## 3계층 아키텍처

- `raw/` — 불변 입력 문서 (LLM이 읽기만, 수정 금지)
- `wiki/*.md` — LLM이 생성·유지하는 마크다운 (요약, 엔티티 페이지, 개념 비교, 마스터 인덱스)
- `CLAUDE.md` — 스키마·컨벤션 (위키 구조 정의, 워크플로 지시)

## 3가지 핵심 연산

| 연산 | 설명 |
|------|------|
| Ingest | 소스를 넣으면 LLM이 10~15개 위키 페이지를 업데이트 |
| Query | LLM이 인덱스를 검색하고 답변을 합성 |
| Lint | 주기적 건강 점검 — 모순, 부실 주장, 고아 페이지 탐지 |

## 본 구현의 확장 결정

### 1. `wiki/` 노출형 선택

Karpathy 원본은 디렉토리 이름을 엄격히 규정하지 않는다. 본 구현은 워크스페이스 CLAUDE.md의 "LLM Wiki 활용 규칙"이 `wiki/index.md` 존재를 시그널로 쓰도록 규정하므로 노출형 `wiki/`를 채택. Obsidian에서 vault로 직접 열 수 있는 이점도 있다.

### 2. 명령 8개로 확장

Karpathy 원본 3개(Ingest/Query/Lint) + 본 구현 추가 5개:
- `init` — 구조 자동 생성 (Karpathy는 수동 설명만)
- `sync` — `index.md` 결정론적 재빌드 (LLM 오류 방지)
- `export` — 온보딩/ADR/릴리스 노트 템플릿 출력
- `qmd-index` — 하이브리드 검색 백엔드 설정
- `lancedb-sync` — Phase 3 벡터 인덱스

### 3. qmd 통합 (Karpathy 권장)

Karpathy가 LLM Wiki 글에서 qmd를 명시적으로 추천. 본 구현은 qmd 설치 감지 시 자동으로 하이브리드 검색으로 승격, 미설치 시 INDEX.md 라우팅으로 graceful degrade.

### 4. LanceDB는 선택적

Karpathy는 벡터 DB를 명시적으로 배제했다. 이유: 잘 큐레이션된 INDEX.md + LLM 컨텍스트 윈도우가 개인 규모 위키에는 충분. 본 구현도 이 원칙을 존중하여 500페이지 초과 또는 멀티 에이전트 시나리오에서만 권장.

### 5. Obsidian 호환 (`[[wiki-link]]`)

표준 Obsidian 링크 형식을 채택. 사용자가 `wiki/`를 Obsidian vault로 열면:
- 그래프 뷰로 교차 참조 시각화
- 네이티브 링크 follow
- 마크다운 실시간 프리뷰
- 백링크 자동 추적

## 규모별 전략

| 규모 | 전략 |
|------|------|
| <100 페이지 | Karpathy 원본 (INDEX.md + LLM 컨텍스트 윈도우만) |
| 100~500 페이지 | qmd 하이브리드 검색 활용 |
| 500+ 페이지 | LanceDB + DuckDB + Embedding Atlas 추가 |

규모 성장에 따라 단계적으로 추가할 수 있도록 설계됨. Phase 1 사용자가 Phase 2로 업그레이드하려면 `qmd install` + `llm-wiki qmd-index` 한 번만 실행하면 된다.

## 참고

- Karpathy 원문: https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f
- Karpathy 트윗: https://x.com/karpathy/status/2039805659525644595
- 기존 LLM Wiki 구현 사례:
  - `github.com/tinworks-ai/claude-obsidian` (358+ 스타, 8-카테고리 린트)
  - `github.com/llm-wiki/kb-wiki` (npm 패키지, MCP 네이티브)
  - `github.com/khoj-ai/khoj` (25K+ 스타, 오픈소스 세컨드 브레인)
