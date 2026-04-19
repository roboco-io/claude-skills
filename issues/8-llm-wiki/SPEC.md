# Issue #8: llm-wiki 스킬 스펙

> **스코프**: Karpathy LLM Wiki 패턴 + qmd 하이브리드 검색(Phase 2) + LanceDB 선택적 벡터 인덱스.
> **출발점**: `wjtb-cmc`의 `llm-wiki` 스킬 포팅 + 일반화.
> **이슈**: #8

## 1. 개요

### 1.1 목적

프로젝트 문서(스펙/ADR/회의록/코드 설명 등)를 `wiki/raw/`에 모으고 LLM이 컴파일하여 `wiki/`에 교차참조된 마크다운 위키를 생성·유지한다. **검색이 아닌 컴파일**이 핵심 — 한 번 이해한 지식을 계속 다듬어 복리로 축적한다.

### 1.2 핵심 가치

- **복리 지식 축적**: RAG가 매번 재발견하는 반면, 위키는 한 번 정리한 지식을 계속 갱신
- **Obsidian 호환**: `[[wiki-link]]` 형식, 그래프 뷰 가능
- **qmd 하이브리드 검색**: BM25 + 벡터 + LLM 재순위 (설치 시 자동 활성)
- **선택적 벡터 인덱스**: LanceDB + DuckDB + Embedding Atlas (대규모 위키 대응)
- **Graceful degrade**: qmd 없어도 INDEX.md 라우팅으로 작동
- **워크스페이스 컨벤션 정렬**: `wiki/` 노출형, 워크스페이스 CLAUDE.md의 "LLM Wiki 활용 규칙"과 일치

---

## 2. 아키텍처

### 2.1 스킬 배치

```text
plugins/documentation/skills/llm-wiki/
├── SKILL.md                              # 메인 지침 (~300줄)
├── references/
│   ├── page-templates.md                 # 6개 페이지 유형 템플릿 (포팅)
│   ├── ingest-workflow.md                # 인제스트 5단계 상세 가이드 (포팅)
│   ├── claude-md-block.md                # CLAUDE.md 추가 블록 템플릿 (포팅 + wiki/ 반영)
│   ├── qmd-integration.md                # qmd 설치·컨텍스트·검색 옵션 (신규)
│   ├── lancedb-integration.md            # LanceDB + Embedding Atlas 연결 (신규)
│   └── karpathy-pattern.md               # 원본 패턴 + 본 구현 결정 기록 (신규)
└── scripts/
    ├── init.sh                           # wiki/ 구조 초기화 (포팅)
    ├── sync_index.py                     # wiki/index.md 자동 재빌드 (포팅)
    ├── lint_wiki.py                      # 끊어진 링크·고아·frontmatter 검증 (포팅)
    ├── qmd_index.sh                      # qmd 인덱스 빌드/갱신 래퍼 (신규)
    └── lancedb_sync.py                   # LanceDB 벡터 인덱스 동기화 (신규)
```

### 2.2 카테고리 및 등록

- `plugins/documentation/` (기존)
- `.claude-plugin/marketplace.json` documentation.skills 배열에 추가
- `plugin.json` 그대로 유지 (버전 bump은 릴리스 시)

### 2.3 디렉토리 컨벤션 (프로젝트 쪽)

사용자 프로젝트 루트에 생성되는 구조:

```text
{user-project}/
├── wiki/                                 # 노출형 (워크스페이스 CLAUDE.md 규칙)
│   ├── index.md                          # 자동 재빌드 (sync_index.py)
│   ├── log.md                            # ingest 이력
│   ├── raw/                              # 원본 소스 드롭존 (불변)
│   │   └── YYYY-MM-DD_{source}.md
│   ├── {page}.md                         # 컴파일된 위키 페이지 (LLM 관리)
│   └── .gitignore                        # raw/private/** 등
├── CLAUDE.md                             # "LLM Wiki 활용 규칙" 블록 추가
└── ...
```

---

## 3. 명령어 세트 (8개)

| 명령 | 역할 | 구현 위치 | qmd 필요? |
|------|------|----------|-----------|
| `init` | `wiki/` 구조 + `wiki/index.md` + `CLAUDE.md` 블록 생성 | `scripts/init.sh` | 아니오 |
| `ingest <source>` | `raw/`에 드롭된 소스를 LLM이 컴파일, 10-15 페이지 갱신 | SKILL.md 워크플로 + `references/ingest-workflow.md` | 아니오 |
| `query <질문>` | qmd 있음 → 하이브리드 검색 → LLM 합성 / qmd 없음 → INDEX.md 2-hop 라우팅 | SKILL.md 워크플로 | **선택(graceful)** |
| `lint` | 끊어진 `[[link]]`, 고아 페이지, frontmatter 불완전 탐지 | `scripts/lint_wiki.py` | 아니오 |
| `sync` | `wiki/index.md` 자동 재빌드 | `scripts/sync_index.py` | 아니오 |
| `export <template>` | 온보딩/ADR 요약/릴리스 노트 등 템플릿 기반 출력 | SKILL.md 워크플로 | 아니오 |
| `qmd-index` | qmd 인덱스 빌드/갱신 (`qmd index`) | `scripts/qmd_index.sh` | **예** |
| `lancedb-sync` | 선택적 LanceDB 벡터 인덱스 동기화 | `scripts/lancedb_sync.py` | LanceDB |

### 3.1 명령 설계 원칙

- Phase 1 핵심 6개는 qmd 독립적으로 작동
- Phase 2 확장 2개는 추가 의존성 명시적
- `query`는 환경 감지로 자동 분기 (graceful degrade)
- 모든 명령은 `argument-hint` frontmatter에 명시

### 3.2 argument-hint

```yaml
argument-hint: [init|ingest|query|lint|sync|export|qmd-index|lancedb-sync] [args]
```

---

## 4. Graceful Degrade 매트릭스

| 환경 | `init` | `ingest` | `query` | `lint` | `sync` | `export` | `qmd-index` | `lancedb-sync` |
|------|--------|----------|---------|--------|--------|----------|-------------|-----------------|
| 최소 (bash+Python 표준) | ✅ | ✅ | ✅ (INDEX.md 라우팅) | ✅ | ✅ | ✅ | ⚠️ 설치 안내 | ⚠️ 설치 안내 |
| qmd 설치됨 | ✅ | ✅ | ✅ (하이브리드) | ✅ | ✅ | ✅ | ✅ | ⚠️ 설치 안내 |
| qmd + LanceDB 설치됨 | ✅ | ✅ | ✅ (하이브리드 + 벡터 가산) | ✅ | ✅ | ✅ | ✅ | ✅ |

### 4.1 감지 로직

- `command -v qmd` → qmd 사용 가능 여부
- `python3 -c "import lancedb"` → LanceDB 설치 여부
- `init` 실행 시 감지 결과를 CLAUDE.md 블록에 기록하여 세션 간 재활용

### 4.2 사용자 안내 메시지

- qmd 없음 + `query`: **graceful degrade** — "qmd 미감지. INDEX.md 라우팅 모드로 계속 진행. 하이브리드 검색 원하면 `brew install qmd` 또는 `npm install -g @tobilu/qmd`." (exit 0, 계속 동작)
- qmd 있음 + `qmd-index` 미실행 + `query`: "qmd 인덱스 없음. `/llm-wiki qmd-index` 먼저 실행 권장." (exit 0, INDEX.md fallback)
- `qmd-index` 호출인데 qmd 없음: "qmd 미설치. 설치 후 재시도." (exit 1 — 명시적 명령이므로 실패 고지)
- `lancedb-sync` 호출인데 LanceDB 없음: "`pip install lancedb duckdb` 실행 후 재시도." (exit 1 — 명시적 명령)

**원칙**: `query`는 항상 작동하도록 degrade, 설치 전제 명시 명령(`qmd-index`, `lancedb-sync`)은 의존성 없으면 실패 고지.

---

## 5. references/ 내용

### 5.1 page-templates.md (포팅)

6개 페이지 유형: concept / decision / entity / meeting / policy / comparison
각 템플릿에 frontmatter 예시 + 본문 구조.

### 5.2 ingest-workflow.md (포팅)

5단계 인제스트:
1. 소스 읽기
2. 엔티티/개념 추출
3. 기존 wiki 페이지와 교차 참조 검토
4. 페이지 생성/갱신
5. log.md 기록

### 5.3 claude-md-block.md (포팅 + 수정)

사용자 프로젝트 CLAUDE.md에 추가되는 블록. `wiki/` 경로 사용 반영.

### 5.4 qmd-integration.md (신규)

- qmd 설치: `brew install qmd` (macOS), `npm install -g @tobilu/qmd` (기타)
- 컨텍스트 트리 등록: `qmd context add qmd://wiki "<설명>"`
- 검색 모드 3종: `search`(BM25), `vsearch`(벡터), `query`(하이브리드)
- MCP 서버: Claude Code 네이티브 연동
- 스마트 청킹 설정 권장값

### 5.5 lancedb-integration.md (신규)

- 설치: `pip install lancedb duckdb`
- 임베딩 모델 선택 (기본 nomic-embed-text, 다국어 필요 시 Qwen3-Embedding)
- `.lance` 파일 위치: `wiki/.lancedb/`
- Embedding Atlas 연결: `pip install embedding-atlas` + `atlas open wiki/.lancedb/`
- SQL 분석 쿼리 예시 ("지난 7일 미업데이트", "confidence low")

### 5.6 karpathy-pattern.md (신규)

- Karpathy 원본 gist 요약
- 본 구현의 결정 기록:
  - 왜 `wiki/`인가 (`.wiki/` 대신 — 워크스페이스 규칙 일치)
  - 왜 qmd인가 (Karpathy 추천)
  - LanceDB 선택적 이유 (Phase 3)
- 복리 축적 vs RAG 대조 설명

---

## 6. scripts/ 상세

### 6.1 init.sh

- 작업: `wiki/`, `wiki/raw/`, `wiki/.gitignore` 생성 + `wiki/index.md`, `wiki/log.md` 초기 파일
- `CLAUDE.md` 존재 확인, 없으면 `references/claude-md-block.md` 내용으로 생성, 있으면 블록 append
- qmd/LanceDB 감지 결과 로깅

### 6.2 sync_index.py

- 입력: `wiki/*.md` 스캔
- 출력: `wiki/index.md` 재빌드 (페이지 제목, 태그, 카테고리별 그룹)
- 표준 라이브러리만 사용 (pyyaml은 번들 또는 대체 파싱)

### 6.3 lint_wiki.py

- 검사 항목:
  - `[[wiki-link]]` 대상 존재 여부
  - 고아 페이지 (INDEX.md에서 링크되지 않음)
  - frontmatter 필수 필드 (`title`, `updated`) — `created`, `status`는 권장(필수 아님)
  - confidence 신뢰도 낮은 페이지 플래그
- 출력: 표준출력 리포트 + exit code (0=green, 1=issues)

### 6.4 qmd_index.sh (신규)

- `qmd index wiki/` 호출
- qmd 없으면 설치 안내 및 exit 0 (에러 아님 — graceful)

### 6.5 lancedb_sync.py (신규)

- `wiki/*.md` → 임베딩 생성 → LanceDB 테이블 갱신
- `.lancedb/` 디렉토리에 저장
- `lancedb`/`duckdb` 미설치 시 pip 명령 출력 + exit 1

---

## 7. 통합 포인트

### 7.1 워크스페이스 CLAUDE.md "LLM Wiki 활용 규칙"

워크스페이스 CLAUDE.md는 이미 `wiki/` + `wiki/index.md` 존재를 LLM Wiki 사용 시그널로 규정함. 본 스킬이 이 규칙을 실제 실행 가능하게 함.

SKILL.md description에 이 연동을 명시:
> "워크스페이스 CLAUDE.md의 LLM Wiki 활용 규칙을 실행 가능하게 하는 스킬"

### 7.2 `qa-merge` 스킬과의 파이프라인

```
qa (Q&A 카드 저장) → qa-list (목록) → qa-merge (통합 문서)
                                          ↓
                                        raw/ 드롭
                                          ↓
                                    llm-wiki ingest
                                          ↓
                                      wiki/*.md
```

SKILL.md에 "qa-merge 출력은 raw/의 유력 후보"로 명시.

### 7.3 `intent` 스킬과의 연결

`INTENT.md` → `raw/intent.md`로 복사 시 ingest 대상. Why/What/Not/Learnings 섹션이 위키의 entity/decision 페이지로 분해.

### 7.4 `korean-docs` 스킬과의 직교성

한국어 출력 규칙은 독립. 위키 내용은 한국어 가능, 페이지 식별자(제목, `[[link]]`)는 영어 식별자 허용 (Obsidian 호환).

---

## 8. Obsidian 호환

### 8.1 링크 형식

- `[[page-name]]` — Obsidian 네이티브
- `[[page-name|display text]]` — 별칭 링크

### 8.2 그래프 뷰

사용자는 Obsidian으로 `wiki/` vault를 열어 교차 참조 시각화 가능. 본 스킬이 생성하는 마크다운이 Obsidian 호환 표준.

### 8.3 제약

- frontmatter 날짜는 ISO 8601 (`YYYY-MM-DD`)
- 코드 블록은 펜스 fenced (` ``` `)
- 수식은 LaTeX 인라인 `$...$` 또는 블록 `$$...$$`

---

## 9. 검증 사례 및 인용 규칙

### 9.1 외부 레퍼런스

- Karpathy LLM Wiki gist: https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f
- qmd: https://github.com/tobi/qmd
- LanceDB: https://lancedb.com
- Apple Embedding Atlas: https://github.com/apple/embedding-atlas
- Anthropic Contextual Retrieval: https://anthropic.com/news/contextual-retrieval

### 9.2 내부 레퍼런스

- 포팅 원본: `wjtb-cmc/.claude/skills/llm-wiki/` (로컬, commit 고정 필요)
- 리서치 리포트: `~/Downloads/llm-wiki-qmd-vectordb-complete-report.md`

### 9.3 인용 라벨

- `[Karpathy]` — Karpathy gist 원문
- `[qmd]` — qmd 공식 문서
- `[LanceDB]` — LanceDB 공식
- `[Port: wjtb-cmc]` — 포팅 출처 표시

---

## 10. Non-Goals

- **RAG 벡터 검색 전용**: Karpathy 원칙 준수, RAG보다 컴파일 우선
- **멀티 프로젝트 통합 위키**: 단일 프로젝트 위키만. 멀티는 향후
- **Web UI**: Obsidian 또는 기존 마크다운 뷰어로 대체
- **실시간 파일 워처**: `sync`/`lint` 수동 호출 방식
- **LLM 모델 번들**: qmd/LanceDB 모델은 외부 의존
- **LEP·wjtb-cmc 특수 로직 유지**: 포팅 시 전부 일반화

---

## 11. 성공 기준

### 11.1 기능

- [ ] `init`으로 새 프로젝트에 `wiki/` 구조 생성 성공
- [ ] 샘플 소스(라이트페이퍼 1개) `ingest` 실행 시 5-10 페이지 생성, `[[link]]` 교차참조 정상
- [ ] `lint` 실행 시 끊어진 링크·고아 페이지 탐지
- [ ] `sync` 실행 시 `index.md` 재빌드
- [ ] qmd 설치 환경에서 `query` 하이브리드 검색 동작
- [ ] qmd 미설치 환경에서 `query` INDEX.md 라우팅으로 fallback
- [ ] LanceDB 설치 환경에서 `lancedb-sync` 성공 + Embedding Atlas 연결 가능

### 11.2 통합

- [ ] `npm test` 197+ tests green (마켓플레이스 등록 후 증가분 포함)
- [ ] `plugins/documentation/README.md`에 llm-wiki 행 추가
- [ ] root `README.md`에 llm-wiki 등록
- [ ] CHANGELOG `[Unreleased]` 엔트리

### 11.3 워크스페이스 규칙 반영

- [ ] 워크스페이스 CLAUDE.md의 "LLM Wiki 활용 규칙"이 본 스킬을 통해 실행 가능

---

## 12. 인터뷰 요약 (설계 결정 기록)

| 항목 | 결정 |
|------|------|
| 스코프 | Phase 2 — qmd 필수 + LanceDB 선택 |
| 스킬 구조 | 단일 스킬 (8개 서브커맨드) |
| 디렉토리 | `wiki/` 노출형 (워크스페이스 CLAUDE.md 규칙 일치) |
| 카테고리 | `documentation/` |
| qmd fallback | Graceful degrade → INDEX.md 라우팅 |
| 출발점 | `wjtb-cmc` 스킬 포팅 + 일반화 |
| 언어 | bash + Python 표준 라이브러리 중심 |
| Obsidian 호환 | `[[wiki-link]]` 표준 |
| qa-merge 파이프라인 | `raw/` 드롭 지점으로 명시 |

---

## 13. Open Questions (구현 단계에서 결정)

- **scripts의 Python 버전**: 3.8+ vs 3.10+ — wjtb-cmc 기존 기준 따름, 확인 필요
- **frontmatter 파싱**: pyyaml 의존 vs 표준 라이브러리 수동 파싱 — 후자 권장 (zero-dep)
- **Embedding Atlas 버전**: 2026 시점 MIT 버전 기준, 주기적 재확인
- **qmd 브루 탭**: 공식 brew tap 여부 재확인, 없으면 npm 경로 우선
- **LanceDB 스키마**: 임베딩 차원, 메타데이터 컬럼 명세 — 구현 시 결정

---

*설계 기준 일자: 2026-04-19.*
*근거: `~/Downloads/LLM_WIKI_HANDOFF.md`, `~/Downloads/llm-wiki-qmd-vectordb-complete-report.md`, 워크스페이스 CLAUDE.md "LLM Wiki 활용 규칙".*
