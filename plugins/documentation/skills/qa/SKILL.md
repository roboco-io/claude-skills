---
name: qa
description: Record Q&A about technical concepts with structured documentation. Use when users ask about mathematical, technical, or domain-specific concepts and want the explanation saved as a reference document.
---

# Q&A Recording Skill

기술적/수학적 개념에 대한 질문과 답변을 구조화된 문서로 기록합니다.

## 사용법

```
/qa <질문 또는 개념>
```

## 예시

```
/qa Persistent Homology가 뭐야?
/qa Takens embedding의 수학적 원리
/qa Simplicial complex와 graph의 차이점
/qa React Server Components 동작 방식
```

## 동작

1. 전달된 질문/개념을 분석하고 카테고리 분류
2. 체계적이고 명확한 답변 작성
3. `docs/qa/` 디렉토리에 마크다운 파일로 저장

## 파일 저장 규칙

- **파일명**: `YYYYMMDD-HHMMSS-<slug>.md`
  - 예: `20260118-143052-persistent-homology.md`
- **저장 위치**: `docs/qa/`
- 디렉토리가 없으면 자동 생성

## 파일 구조

```markdown
---
date: YYYY-MM-DD HH:MM:SS
tags: [관련 태그들]
category: <카테고리>
---

# Q: <질문>

## A: <답변 제목>

<상세 설명>

### 핵심 개념
- ...

### 수학적 정의 (해당시)
- ...

### 예시
- ...

### 관련 개념
- ...
```

## 카테고리 분류

| 카테고리 | 설명 | 예시 |
|----------|------|------|
| `math` | 수학 전반 | 선형대수, 미적분, 확률론 |
| `topology` | 위상수학 | Persistent Homology, Simplicial Complex |
| `algebra` | 대수학 | Tensor, Matrix Decomposition |
| `geometry` | 기하학 | Manifold, Embedding |
| `ml` | 머신러닝 | Neural Network, Optimization |
| `statistics` | 통계학 | Bayesian, Hypothesis Testing |
| `cs` | 컴퓨터 과학 | Algorithm, Data Structure |
| `web` | 웹 기술 | React, HTTP, REST |
| `infra` | 인프라 | Docker, Kubernetes, AWS |
| `general` | 기타 | 분류 불가한 항목 |

## 작성 지침

1. **직관성**: 12살도 이해할 수 있게 직관적으로 설명. 일상적인 비유와 쉬운 예시를 먼저 제시
2. **명확성**: 직관적 설명 후 학문적 엄밀성을 갖춘 정의 제공
3. **구조화**: 직관적 설명 → 정의 → 예시 → 응용 순서로 설명
4. **시각화**: 가능하면 Mermaid 다이어그램 (흑백) 사용
5. **연결성**: 관련 개념이 있으면 언급
6. **실용성**: 현재 프로젝트와의 연관성이 있으면 언급

## 실행 절차

1. 질문 분석 및 카테고리 분류
2. 체계적인 답변 작성
3. `docs/qa/` 디렉토리 확인 (없으면 생성)
4. 파일 저장
5. 저장 완료 메시지 출력

질문: $ARGUMENTS
