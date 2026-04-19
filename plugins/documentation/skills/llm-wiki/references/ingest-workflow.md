> **Snapshot date**: 2026-04-19
> **Description**: Ingest 5단계 상세 가이드

# Ingest 5단계 상세

`llm-wiki ingest {source}` 호출 시 따르는 단계별 프로토콜.

---

## 1. 수집 (Collect)

**입력 형태별 처리:**

- **로컬 파일**: `cp {source} wiki/raw/$(date +%F)_{basename}`
  이미 같은 경로에 있으면 건너뛰고 경고.
- **URL**: WebFetch로 가져와 `wiki/raw/$(date +%F)_{slug}.md`에 저장.
  frontmatter에 `source_url`을 꼭 남긴다.
- **대화/메모**: 사용자가 붙여넣은 텍스트는 `wiki/raw/$(date +%F)_note_{topic}.md`로 저장.
- **기존 프로젝트 문서** (`docs/architecture.md` 등): 원본을 복사하지 않고
  `wiki/raw/$(date +%F)_ref_{name}.md`에 **포인터만** 기록:
  ```markdown
  # Pointer: docs/architecture.md
  source: ../../docs/architecture.md
  ingested_at: YYYY-MM-DD
  ```
  프로젝트 내부 문서는 중복 저장하지 말고 포인터로 다룬다.

**금지**:
- raw/ 파일을 사후 편집 — 갱신은 새 날짜 파일을 만들어라.
- 바이너리/이미지 raw 보관 — 별도 경로에 두고 경로만 적어라.

---

## 2. 추출 (Extract)

**먼저 기존 위키를 읽는다.**

1. `wiki/index.md`를 Read해 현재 페이지 목록 파악
2. 원본에서 다루는 주제의 키워드로 기존 페이지 존재 여부 확인
3. 원본에서 아래 유형의 정보를 식별:
   - **개념/용어** → concept
   - **시스템 컴포넌트/서비스** → entity
   - **결정/선택/트레이드오프** → decision
   - **회의·논의 요약** → meeting
   - **규칙/정책/요구사항** → policy
   - **대안 비교** → comparison

**중복 판단 기준:**
- 제목이 같거나 alias가 겹치면 **갱신**
- 동일 주제지만 관점이 다르면 **관련 링크**로 연결하고 분리 생성
- 판단이 애매하면 사용자에게 확인

---

## 3. 작성 (Write)

- `references/page-templates.md`에서 유형에 맞는 템플릿 선택
- 프론트매터 필수 필드 모두 채움:
  - `title`, `type`, `status`, `confidence`, `last_updated`, `sources`
- 본문은 가급적 `[[wiki-link]]`로 다른 페이지와 연결
- 확신이 낮은 부분은 `confidence: low` + 본문에 `> ⚠ 확인 필요:` 표기
- 아직 존재하지 않는 대상 페이지는 `[[새페이지#stub]]`로 남겨둠
  (lint가 stub 감지 → 다음 ingest에서 실체화)

**갱신 시 원칙**:
- 기존 본문을 통째로 덮어쓰지 않는다. 변경 섹션만 교체하거나 추가.
- `last_updated`를 오늘 날짜로
- `sources:`에 새 raw 경로를 append
- `confidence`는 상향만, 사용자 지시 없이 하향 금지

---

## 4. 기록 (Log)

`wiki/log.md`에 한 줄 추가:

```
- YYYY-MM-DD | wiki/raw/YYYY-MM-DD_source.md | +3 ~2 | Rate Limiter 토큰버킷 정책 추출
```

- `+N`: 새로 만든 페이지 수
- `~N`: 갱신한 페이지 수
- 요약: 20자 내외, 한국어 OK

---

## 5. 동기화 (Sync & Lint)

순서대로 실행:

```bash
python .claude/skills/llm-wiki/scripts/sync_index.py
python .claude/skills/llm-wiki/scripts/lint_wiki.py
```

**결과 처리:**

- `sync_index.py`: 새 페이지가 index에 반영되었는지 출력 확인
- `lint_wiki.py`:
  - 끊어진 링크 → 타겟을 stub으로 바꾸거나 해당 페이지를 즉시 생성
  - 고아 페이지 → index.md는 자동 처리되지만, 다른 페이지에서 `[[링크]]`를 걸 기회를 찾는다
  - frontmatter 누락 → 즉시 수정
  - stale draft → 사용자에게 보고 (자동 갱신 금지)

**ingest 완료 보고 포맷** (사용자에게):

```
✓ ingest 완료: {source}
  • 저장: wiki/raw/{path}
  • 새 페이지: [[Rate Limiter]], [[Token Bucket]]
  • 갱신: [[User Authentication]]
  • lint: broken 0, orphan 1, stub 2
  • 다음 제안: {stub 페이지 중 우선순위 높은 것}을 ingest 하시겠습니까?
```

---

## 실패 모드와 회피

| 증상 | 원인 | 대응 |
|---|---|---|
| 같은 개념이 여러 페이지로 파편화 | 단계 2에서 기존 페이지 확인 누락 | 매 ingest마다 index.md를 먼저 Read |
| 링크 무덤 (링크만 있고 내용 없음) | 템플릿 채우기 회피 | confidence: low라도 본문 최소 3문장 |
| raw/ 폭발 | 매번 원본 복사 | 프로젝트 내부 문서는 포인터로 |
| 갱신했는데 log가 비어있음 | 4단계 생략 | ingest 완료 전 log.md 반드시 커밋 |
