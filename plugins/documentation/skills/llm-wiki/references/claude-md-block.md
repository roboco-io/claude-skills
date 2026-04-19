## LLM Wiki 활용 규칙

이 프로젝트는 `wiki/` 디렉토리에 `[[wiki-link]]` 교차참조 위키를 유지한다. Karpathy LLM Wiki 패턴을 따른다.

### 작업 시 우선순위

1. **위키 우선 참조**: 질문에 답하거나 작업을 시작할 때, `wiki/index.md`에서 관련 페이지를 먼저 찾아 읽는다. `[[wiki-link]]`를 따라 2-hop까지 확장하여 맥락을 파악한다.
2. **출처 인용**: 답변 작성 시 위키 페이지를 `[[페이지 제목]]` 형태로 인용한다.
3. **위키에 없으면 명시**: 위키에 답이 없으면 "위키에 없음"이라 표기하고 `wiki/raw/` 또는 외부 원본을 읽어 보강한다. 새 내용이면 `llm-wiki ingest`로 위키를 성장시킨다.
4. **검색보다 컴파일**: 매번 원본을 다시 읽지 말고, 이미 컴파일된 위키 지식을 적극 재활용한다.

### 위키 구조

- `wiki/index.md` — 자동 재빌드되는 라우팅 레이어 (수동 편집 금지)
- `wiki/{page}.md` — 컴파일된 지식 페이지 (`[[wiki-link]]` 교차참조)
- `wiki/raw/` — 원본 소스 드롭존 (불변)
- `wiki/log.md` — ingest 이력
- `wiki/.lancedb/` — 선택적 벡터 인덱스 (lancedb-sync 실행 시)

### 스킬 명령

사용자가 `llm-wiki <command>`를 호출하면 해당 단계 실행:
- `init` — 구조 초기화
- `ingest <source>` — 새 소스를 컴파일해 위키 갱신
- `query <질문>` — 하이브리드 검색(qmd) 또는 INDEX.md 라우팅
- `lint` — 끊어진 링크·고아 페이지 탐지
- `sync` — index.md 재빌드
- `export <template>` — 온보딩·ADR 요약 등 출력
- `qmd-index` — qmd 인덱스 빌드 (선택)
- `lancedb-sync` — LanceDB 벡터 인덱스 동기화 (선택)
