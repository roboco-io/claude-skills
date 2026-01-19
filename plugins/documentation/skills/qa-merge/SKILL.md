---
name: qa-merge
description: Merge all saved Q&A documents into a single consolidated reference document. Use when users want to create a comprehensive concepts reference from individual Q&A files.
---

# Q&A Merge Skill

저장된 모든 Q&A 문서를 하나의 통합 문서로 병합합니다.

## 사용법

```
/qa-merge [옵션]
```

## 옵션

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `--by-category` | 카테고리별로 그룹화 | 기본값 |
| `--by-date` | 날짜순으로 정렬 | - |
| `--output <파일명>` | 출력 파일명 지정 | `docs/CONCEPTS.md` |

## 동작

1. `docs/qa/` 디렉토리의 모든 Q&A 파일 스캔
2. 각 파일의 frontmatter에서 메타데이터 추출
3. 지정된 방식으로 정렬/그룹화
4. 목차 생성
5. 통합 문서 작성 및 저장

## 출력 구조

```markdown
# 개념 정리 (Concepts Reference)

> 이 문서는 프로젝트 진행 중 학습한 수학적/기술적 개념들을 정리한 것입니다.
> 자동 생성됨: YYYY-MM-DD HH:MM:SS

## 목차

- [Math](#math)
  - [Linear Algebra Basics](#linear-algebra-basics)
- [Topology](#topology)
  - [Persistent Homology](#persistent-homology)
  - [Simplicial Complex](#simplicial-complex)
- [ML](#ml)
  - [Transformer Architecture](#transformer-architecture)
...

---

## Math

### Linear Algebra Basics

**Q: 선형대수의 기초 개념은?**

<답변 내용>

---

## Topology

### Persistent Homology

**Q: Persistent Homology가 뭐야?**

<답변 내용>

---
```

## 카테고리 순서

1. math
2. topology
3. algebra
4. geometry
5. ml
6. statistics
7. cs
8. web
9. infra
10. general

## 실행 절차

1. `docs/qa/` 디렉토리 스캔
2. 각 파일의 frontmatter 파싱
3. 옵션에 따라 정렬/그룹화
4. 목차 생성
5. 통합 문서 작성
6. 지정된 경로에 저장 (기본: `docs/CONCEPTS.md`)
7. 저장 완료 메시지 출력

## 에러 처리

- `docs/qa/` 디렉토리가 없으면: "Q&A 문서가 없습니다. /qa 명령어로 먼저 Q&A를 생성하세요."
- 파일이 없으면: "병합할 Q&A 문서가 없습니다."

옵션: $ARGUMENTS
