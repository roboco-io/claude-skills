> **Snapshot date**: 2026-04-19
> **Description**: 위키 페이지 6개 유형 템플릿 (concept/decision/entity/meeting/policy/comparison)

# 페이지 템플릿

ingest 단계에서 페이지 유형을 고르고 아래 템플릿 중 하나를 채워 `wiki/{slug}.md`에 저장한다.
`last_updated`는 오늘 날짜, `sources`는 raw 파일 경로를 반드시 기록한다.

---

## 1. concept — 개념/아이디어/설명

```markdown
---
title: {개념명}
aliases: [{영문명}, {약어}]
type: concept
status: stable
confidence: high
last_updated: YYYY-MM-DD
sources:
  - wiki/raw/YYYY-MM-DD_source.md
related: [[{related-page}]]
---

# {개념명}

> 한 줄 정의.

## 배경
왜 이 개념이 존재하는가.

## 핵심 내용
- 요점 1 ([[관련 페이지]])
- 요점 2

## 주의사항 / 오해
흔히 틀리는 부분.

## 참고
- 출처 링크
```

**예시 주제**: Rate Limiter, Token Bucket, JWT, Idempotency Key.

---

## 2. entity — 시스템 엔티티/컴포넌트/서비스

```markdown
---
title: {엔티티명}
aliases: [{영문명}, {약어}]
type: entity
status: stable
confidence: medium
last_updated: YYYY-MM-DD
sources:
  - wiki/raw/...
related: [[User Authentication]], [[Payment Processor]]
---

# Rate Limiter — API 속도 제한 서비스

## 책임
이 엔티티가 담당하는 범위.

## 인터페이스
- Input: `request(user_id, endpoint) → allow | deny`
- Config: `limits.yaml` (endpoint 별 RPS 임계치)

## 내부 구조
- [[Token Bucket]] 알고리즘 사용
- Redis 상태 저장 ([[Redis Cluster]])

## 의존
- [[User Authentication]] — user_id 해석
- [[Metrics Pipeline]] — 거부율 전송

## 코드 위치
- `services/rate-limiter/`
- 주요 파일: {개수}
```

**예시 주제**: Rate Limiter, User Authentication, Payment Processor, Notification Service.

---

## 3. decision — Architectural Decision Record

```markdown
---
title: ADR-{번호} {결정 제목}
type: decision
status: stable      # proposed | stable | deprecated | superseded
confidence: high
last_updated: YYYY-MM-DD
sources:
  - wiki/raw/...
related: [[관련 ADR]], [[영향받은 컴포넌트]]
---

# ADR-{번호}: {결정 제목}

- **일자**: YYYY-MM-DD
- **상태**: Accepted
- **결정권자**: {이름/팀}

## 맥락
왜 결정이 필요했는가.

## 결정
무엇을 결정했는가.

## 대안
- A안: 채택. 근거…
- B안: 기각. 근거…

## 결과
긍정적 결과와 트레이드오프.

## 참고
- 회의록 링크
```

**예시 주제**: "ADR-007 Rate Limiter에 Redis 대신 Memcached 사용", "ADR-012 JWT 서명 알고리즘 RS256으로 전환".

---

## 4. meeting — 회의록/논의 요약

```markdown
---
title: {YYYY-MM-DD} {회의 주제}
type: meeting
status: stable
confidence: medium
last_updated: YYYY-MM-DD
sources:
  - wiki/raw/YYYY-MM-DD_meeting_{topic}.md
related: [[관련 결정]], [[관련 엔티티]]
---

# {회의 제목}

- **일자**: YYYY-MM-DD
- **참석자**: {이름 목록}
- **주제**: 한 줄 요약

## 논의 내용
1. 안건 1 — 결과
2. 안건 2 — 결과

## 결정 사항
- [[ADR-XXX]]로 분리 기록
- 즉시 적용: ...

## 액션 아이템
- [ ] {담당자}: {할 일} — {기한}

## 미결 사안
- 후속 논의 필요한 주제
```

**예시 주제**: "2026-03-14 Payment Processor 재시도 정책 회의", "Rate Limiter SLA 리뷰 킥오프".

---

## 5. policy — 정책/규칙/요구사항

```markdown
---
title: {정책명}
type: policy
status: draft       # draft가 오래되면 lint가 경고
confidence: medium
last_updated: YYYY-MM-DD
sources:
  - wiki/raw/...
related: [[관련 엔티티]]
---

# {정책명}

## 목적
이 정책이 해결하는 문제.

## 규칙
- [ ] 규칙 1
- [ ] 규칙 2

## 적용 범위
- 해당되는 시스템/팀
- 제외 대상

## 위반 시 대응
- 탐지 방법
- 복구 절차

## 미해결 이슈
- 열린 질문
```

**예시 주제**: "신규 가입 계정 Rate Limit 정책", "PCI 결제 데이터 보관 기간 정책", "Access Token 만료 정책".

---

## 6. comparison — 대안 비교/트레이드오프

```markdown
---
title: {주제} 비교 — {옵션 A} vs {옵션 B}
type: comparison
status: stable
confidence: medium
last_updated: YYYY-MM-DD
sources:
  - wiki/raw/...
related: [[관련 결정]], [[관련 개념]]
---

# Rate Limiter 알고리즘 비교 — Token Bucket vs Leaky Bucket

## 요약
각 옵션의 한 줄 요약과 추천 기준.

## 비교표
| 기준 | Token Bucket | Leaky Bucket |
|------|--------------|--------------|
| 버스트 허용 | O | X |
| 구현 복잡도 | 중 | 낮음 |
| 메모리 사용 | 낮음 | 낮음 |
| 평활화 | 부분 | 완전 |

## 사용 맥락
- Token Bucket: API gateway 짧은 버스트 허용
- Leaky Bucket: 다운스트림 보호 (일정 속도 유지)

## 관련 결정
- [[ADR-007]] 본 프로젝트는 Token Bucket 채택

## 참고
- 출처 링크
```

**예시 주제**: "JWT vs Session Token", "OAuth2 vs SAML", "Stripe vs Adyen 결제 처리".

---

## 어떤 템플릿을 선택할지

- 문서가 "무엇인가"를 설명 → **concept**
- 시스템 구성요소/서비스/모듈 단위 → **entity**
- 결정의 이유와 트레이드오프 → **decision**
- 회의·브레인스토밍 결과 → **meeting**
- "반드시 지켜야 하는 규칙" → **policy**
- 두 가지 이상 대안 비교 → **comparison**

애매하면 concept로 시작하고, 내용이 커지면 분할한다.
