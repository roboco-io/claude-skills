---
name: qa-list
description: Display a list of saved Q&A documents. Use when users want to see what Q&A records exist, optionally filtered by category.
---

# Q&A List Skill

저장된 Q&A 문서 목록을 표시합니다.

## 사용법

```
/qa-list [카테고리]
```

## 옵션

- 카테고리 미지정: 전체 목록 표시
- 카테고리 지정: 해당 카테고리만 필터링

## 카테고리

`math`, `topology`, `algebra`, `geometry`, `ml`, `statistics`, `cs`, `web`, `infra`, `general`

## 동작

1. `docs/qa/` 디렉토리 스캔
2. 각 파일의 frontmatter에서 메타데이터 추출
3. 테이블 형태로 목록 표시
4. 카테고리별 통계 출력

## 출력 형식

```markdown
## Q&A 목록

총 N개의 Q&A가 저장되어 있습니다.

| # | 날짜 | 카테고리 | 질문 | 파일 |
|---|------|----------|------|------|
| 1 | 2026-01-18 | topology | Persistent Homology가 뭐야? | 20260118-143052-persistent-homology.md |
| 2 | 2026-01-18 | algebra | Tensor Train 분해란? | 20260118-150023-tensor-train.md |
...

### 카테고리별 통계

| 카테고리 | 개수 |
|----------|------|
| topology | 5 |
| algebra | 3 |
| ml | 2 |
```

## 실행 절차

1. `docs/qa/` 디렉토리 존재 확인
2. 파일 목록 수집
3. 각 파일의 frontmatter 파싱
4. 카테고리 필터 적용 (지정된 경우)
5. 테이블 형식으로 출력
6. 카테고리별 통계 출력

## 에러 처리

- `docs/qa/` 디렉토리가 없으면: "Q&A 문서가 없습니다. /qa 명령어로 먼저 Q&A를 생성하세요."
- 지정한 카테고리에 문서가 없으면: "해당 카테고리의 Q&A가 없습니다."

필터: $ARGUMENTS
