> **Snapshot date**: 2026-04-19
> **Description**: LanceDB 벡터 인덱스 + Embedding Atlas 연결

# LanceDB Integration (Phase 3 optional)

> **When to use**: 위키 규모 500페이지 초과, 멀티 에이전트 지식 슬라이싱, Embedding Atlas 시각화 필요 시. 500페이지 미만은 qmd만으로 충분.

## 설치

```bash
pip install lancedb duckdb sentence-transformers
```

임베딩 모델:
- 기본 `all-MiniLM-L6-v2` — CPU에서 빠름, 영어 중심
- 한국어·다국어 `Qwen3-Embedding-0.6B` — MMTEB 70.58점, 프로덕션 품질

## 인덱스 생성

```bash
./scripts/lancedb_sync.py --wiki-dir ./wiki --model all-MiniLM-L6-v2
```

결과:
- `wiki/.lancedb/` 디렉토리에 `.lance` 파일 생성
- `wiki/.gitignore` 기본적으로 `.lancedb/` 제외 (init.sh에서 자동)

## Embedding Atlas 연결

```bash
pip install embedding-atlas
atlas open wiki/.lancedb/
```

브라우저에서 WebGPU 렌더링으로 수백만 포인트 가시화. 멀티 코디네이트 뷰 교차 필터링. MCP 지원으로 Claude Code 직접 연동 가능.

## DuckDB SQL 분석

LanceDB는 Lance extension for DuckDB를 통해 DuckDB와 네이티브 통합. 데이터 변환 제로:

```
LanceDB (.lance files)
    ↕  Lance extension
DuckDB (shared query engine)
    ↕  Mosaic coordinator
Apple Embedding Atlas (WebGPU visualization)
```

분석 쿼리 예:

```sql
-- 지난 7일 미업데이트 페이지
SELECT path, title, updated
FROM lance_scan('wiki/.lancedb/wiki_pages.lance')
WHERE updated < CURRENT_DATE - INTERVAL '7 days'
ORDER BY updated ASC;

-- 카테고리별 페이지 수
SELECT type, COUNT(*) as n
FROM lance_scan('wiki/.lancedb/wiki_pages.lance')
GROUP BY type
ORDER BY n DESC;

-- 낮은 confidence 페이지
SELECT path, title, confidence
FROM lance_scan('wiki/.lancedb/wiki_pages.lance')
WHERE confidence IN ('low', 'tentative');
```

## 트레이드오프 (report §6.2 요약)

**장점**:
- 시맨틱 디스커버리 (이름을 모르는 관련 개념도 찾음)
- 멀티 에이전트 슬라이싱 (`WHERE project = 'X'` 필터)
- Embedding Atlas로 지식 맵 시각화
- Lance 포맷 자동 버전 관리가 위키 편집 히스토리와 정합
- DuckDB SQL로 분석 쿼리 바로 실행

**단점**:
- 복잡도 비용 (임베딩 모델, 청킹, 인덱스 동기화)
- 듀얼 소스 오브 트루스 (md ↔ vec) — 동기화 지연
- 임베딩 모델 lock-in (모델 바꾸면 전체 재인덱싱)
- LanceDB v0.23.x 베타 상태
- qmd가 이미 거의 같은 검색 문제를 해결

## qmd vs LanceDB

qmd는 BM25 + vector + LLM 재순위를 이미 결합하고 MCP로 에이전트 통합. 설치 zero-dep. 대부분의 경우 qmd만으로 충분.

LanceDB는 다음 요구가 있을 때 추가:
- 500페이지 초과 대규모 위키
- 멀티 프로젝트 에이전트 슬라이싱
- 시각화·SQL 분석·커스텀 랭커 필요

## 단계별 채택

| Phase | 규모 | 전략 |
|-------|------|------|
| 1 | <100 페이지 | 벡터 DB 없이 Karpathy 원본 |
| 2 | 100~500 페이지 | qmd 하이브리드만 |
| 3 | 500+ 페이지 | qmd + LanceDB + Embedding Atlas |

## Reference links

- LanceDB: https://lancedb.com
- Lance DuckDB extension: https://github.com/lancedb/lance-duckdb
- Apple Embedding Atlas: https://github.com/apple/embedding-atlas
- Anthropic Contextual Retrieval: https://anthropic.com/news/contextual-retrieval
