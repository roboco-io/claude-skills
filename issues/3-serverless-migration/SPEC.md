# Issue #3: Serverless Migration Advisor 스킬 스펙 문서

> **스코프**: 기존 always-on 아키텍처를 AWS 서버리스 + Spot 패턴으로 이행하기 위한 **업스트림 어드바이저** 스킬.
> 세부 how-to는 카테고리 내 타 스킬(예: `sagemaker-spot-training`)로 위임한다.
> **검증 근거**: `serverless-autoresearch`(Tier 1, $3.94/48실험), `serverless-openclaw`(Tier 2, ~$1/월).

## 1. 개요

### 1.1 목적

기존 AWS 워크로드(배치/ETL/API/이벤트 기반/모놀리스)를 서버리스 + Spot 조합으로 이행할 때,
트레이드오프를 **AWS 공식문서 기반 근거**와 **실 검증 사례**로 명시해
사용자가 의사결정·리스크 평가·단계별 이행 계획을 세우도록 돕는다.

### 1.2 핵심 가치

- **공식문서 근거 인용**: 모든 트레이드오프 주장은 AWS Docs 섹션 또는 Serverless Lens 원칙으로 traceable.
- **실 검증 사례 연결**: 두 오픈소스 프로젝트 인사이트를 번호화하여 인용 가능.
- **심층 인터뷰 기반**: AskUserQuestion으로 워크로드 제약·위험 허용도를 단계적으로 수집.
- **위임 명확화**: 서비스 확정 후 구현 스킬로 핸드오프. 중복 지식 방지.
- **전 티어 지원**: Tier 1(배치) / Tier 2(API) / Tier 3(모놀리스·데이터) 모두 원칙+패턴 수준으로 다룸.

---

## 2. 아키텍처

### 2.1 스킬 배치

```text
plugins/workflow/skills/serverless-migration-advisor/
├── SKILL.md                                # 메인 지침 (500줄 이하)
└── references/
    ├── tradeoffs-compute.md                # Lambda/Fargate/Batch/SageMaker/EC2 Spot 공식 트레이드오프
    ├── tradeoffs-spot.md                   # Spot 용량/인터럽트/HUGI/billable 정의
    ├── tradeoffs-data-layer.md             # RDS / Aurora Serverless v2 / DynamoDB / S3 Express
    ├── tradeoffs-event-driven.md           # EventBridge / SQS / Kinesis / Step Functions
    ├── serverless-lens.md                  # AWS Well-Architected Serverless Lens 원칙 요약 + 링크
    ├── patterns-tier1-batch.md             # 배치/훈련/ETL 이행 패턴
    ├── patterns-tier2-api.md               # 상시형 API / 웹 이행 패턴
    ├── patterns-tier3-monolith.md          # Strangler Fig, 모놀리스 분해
    ├── patterns-tier3-data.md              # RDS → DynamoDB, CDC 전이
    ├── interview-bank.md                   # Phase별 AskUserQuestion 질문/옵션 풀
    ├── case-study-autoresearch.md          # 48실험 $3.94, H100 229s $0.16
    ├── case-study-openclaw.md              # Lambda + Fargate Spot ~$1/월
    └── source-insights.md                  # 번호화 검증 인사이트 (Insight #N 형식 인용)
```

### 2.2 카테고리 위치

`plugins/workflow/` (이행 프로세스 지향). `development/` 카테고리의 `sagemaker-spot-training`(how-to)과 역할 분리.

### 2.3 메인 스킬 역할

1. **워크로드 분류기**: 인터뷰로 Tier 1/2/3 및 세부 타입 결정.
2. **트레이드오프 서피스**: AWS Docs + 검증 사례 기반으로 각 후보 서비스의 한계 명시.
3. **의사결정 보조**: 비용/지연/관리성/벤더 락인 축으로 후보 비교.
4. **단계별 이행 계획 생성**: 검증-가능한-스테이지 체크리스트.
5. **구현 스킬 위임**: 타겟 확정 후 구현 how-to 스킬로 핸드오프.

---

## 3. 동작 흐름 (5 Phase)

### Phase 1 — 워크로드 분류 인터뷰

AskUserQuestion 질문:
- Q1. 워크로드 타입: `배치/훈련` / `ETL` / `상시 API` / `스케줄 작업` / `이벤트 기반` / `모놀리스` / `기타`
- Q2. 현재 실행 환경: `EC2 24/7` / `EC2 + Auto Scaling` / `ECS/EKS` / `EMR` / `온프레` / `기타`
- Q3. 실행 빈도: `상시` / `일 수회` / `일 1회` / `주·월 단위` / `이벤트 기반 희소`
- Q4. 작업 단위 지속 시간: `<1분` / `1~15분` / `15분~1시간` / `1~8시간` / `>8시간`

### Phase 2 — IaC 스캔 (선택)

사용자가 Terraform / CDK / CloudFormation 파일 경로를 제공하면 정적 분석하여 현 리소스 요약.
제공되지 않으면 스킵하고 Phase 3으로.

### Phase 3 — 제약·리스크 심층 인터뷰

AskUserQuestion 질문 (워크로드 타입별로 질문 집합 분기 — [interview-bank.md](references/interview-bank.md)):

**공통:**
- Q5. 월간 목표 비용 범위
- Q6. RTO / RPO 요구
- Q7. 규정 준수: `PCI-DSS` / `HIPAA` / `GDPR` / `SOC2` / `없음`

**Tier 1 (배치) 특화:**
- Spot 인터럽트 허용도: `허용 (재시도 가능)` / `제한적 (체크포인트 있음)` / `불가`
- 작업 최대 허용 wall-clock

**Tier 2 (API) 특화:**
- 콜드 스타트 허용도 p99: `<500ms` / `<2s` / `<5s` / `허용`
- 지속 연결 필요 여부: WebSocket / SSE / gRPC streaming

**Tier 3 (모놀리스/데이터) 특화:**
- 다운타임 윈도우
- 데이터 일관성 요구: `strong` / `eventual 허용`
- 벤더 락인 허용도

### Phase 4 — 타겟 아키텍처 추천

references/ 참조하여 후보 서비스 매핑:

| 워크로드 | Primary | Secondary | 제외 사유 예 |
|---------|---------|-----------|-------------|
| 배치 훈련 | SageMaker Managed Spot | AWS Batch (Spot) | Lambda 15분 한계 |
| ETL (<15분) | Lambda | Step Functions + Lambda | Batch는 오버헤드 과다 |
| ETL (>15분) | AWS Batch (Spot) | Step Functions + Fargate | Lambda 불가 |
| 상시 API (버스트) | Lambda + API Gateway | Fargate (On-Demand) | ALB 고정비 $18~25/월 |
| 상시 API (대용량 지속) | Fargate | Fargate + Fargate Spot 혼합 | Lambda 6MB 페이로드 한계 |
| 이벤트 처리 | EventBridge + Lambda | Step Functions | - |
| 모놀리스 | Strangler Fig 분해 후 적용 | - | 직접 이행 불가 |

각 매핑에는 **공식문서 인용**과 **Insight #N** 레이블 동반.

### Phase 5 — 리포트 생성

`docs/serverless-migration/YYYY-MM-DD-{topic}.md` 생성.
아래 §5 리포트 구조 참조.

---

## 4. AWS 공식문서 트레이드오프 스냅샷 (2026-04-18 기준)

스킬은 아래 사실들을 `references/tradeoffs-*.md`에 보존하고, 변경 시 수동 리뷰.

### 4.1 Lambda (트레이드오프)

| 항목 | 값 | 출처 |
|------|-----|------|
| 최대 메모리 | 10,240 MB | [Lambda quotas §Function config] |
| 최대 실행 시간 | 900초 (15분) | 동일 |
| 동시 실행 기본 쿼터 | 1,000 | 동일 |
| zip 패키지 | 50MB(zipped) / 250MB(unzipped) | 동일 |
| 컨테이너 이미지 | 최대 10 GB | 동일 |
| /tmp | 512MB~10,240MB | 동일 |
| 동기 페이로드 | 요청·응답 각 6MB | 동일 |
| 스트리밍 응답 | 최대 200MB | 동일 |
| 1 vCPU 등가 | 1,769 MB | 동일 |

**함의 (스킬이 전달):**
- 15분 초과 작업은 Lambda 불가 → Step Functions 또는 Batch로 분해·위임.
- 지속 연결(WebSocket long-lived) 필요 시 Fargate 권장. Lambda는 API Gateway WebSocket으로 메시지 단위만.
- 제공 메모리=CPU 연동이므로 지연 최적화 시 메모리 상향 → CPU도 상향되는 trade-off.

### 4.2 SageMaker Managed Spot Training

| 항목 | 값 |
|------|-----|
| 비용 절감 | on-demand 대비 최대 90% |
| 절감률 공식 | `(1 - BillableTime / TrainingTime) × 100` |
| 필수 조건 | `MaxWaitTime > MaxRuntime` |
| 체크포인트 미사용 시 | 내장·마켓플레이스 알고리즘 `MaxWaitTime ≤ 3600s` |
| 상태 전이 | `Starting → Downloading → Training → (Interrupted → Starting) → Uploading` |

**함의:**
- 인터럽트 허용 워크로드에 한함. 체크포인트 없으면 1시간 한도.
- Billable은 **Training 시간만** 포함 (Starting/Downloading 제외). HUGI 원칙의 AWS 공식 구현.

### 4.3 Fargate Spot

| 항목 | 값 |
|------|-----|
| 인터럽트 경고 | 2분 |
| 신호 | SIGTERM (EventBridge + 컨테이너) |
| `stopTimeout` | 기본 30초, 최대 120초 |
| 정전 시 자동 복구 | 서비스라면 재시도; 단일 태스크는 용량 확보까지 중단 |
| On-Demand fallback | **자동 아님** (사용자가 `capacityProviderStrategy`로 혼합 필요) |

**함의:**
- 단일 태스크 + Fargate Spot = 가용성 위험. 서비스 + `desiredCount ≥ 2` 또는 용량공급자 혼합 필수.
- 2분 내 정리가 가능해야 하므로 SIGTERM 핸들러 의무.

### 4.4 EC2 Spot

| 항목 | 값 |
|------|-----|
| 인터럽트 사유 | Capacity / Price / Constraint |
| 인터럽트 동작 | `terminate` (기본) / `stop` / `hibernate` |
| 경고 | 2분, EventBridge + IMDSv2 메타데이터 |
| Rebalance recommendation | 인터럽트 전 선제 신호 |
| 최대가 지정 시 | 인터럽트 빈도 **증가** |
| 검증 방법 | AWS FIS로 인터럽트 주입 테스트 |

**함의:**
- 최대가 설정은 역효과. 기본(On-Demand 가격 상한)이 최선.
- 리밸런스 시그널 활용하면 사실상 2분보다 긴 여유 확보 가능.
- CloudTrail `BidEvictedEvent`로 사후 감지.

### 4.5 AWS Batch with Spot

| 할당 전략 | 특성 | 추천 |
|-----------|------|------|
| `BEST_FIT` | 최소 가용 인스턴스 | Spot 비추천 (인터럽트률 ↑) |
| `BEST_FIT_PROGRESSIVE` | 용량 부족 시 상위 인스턴스 승격 | 중간 |
| `SPOT_CAPACITY_OPTIMIZED` | 인터럽트 가능성 최소 | **Spot 표준** |

권장 패턴:
- `retryStrategy.attempts ≥ 2` + `evaluateOnExit`로 재시도 사유 구분.
- 큐 우선순위: Spot compute-env 우선, On-Demand compute-env fallback.

### 4.6 AWS Well-Architected Serverless Lens

- `references/serverless-lens.md`에 9개 설계원칙 요약 보관.
- **원칙↔스킬 출력 매핑**:
  - "Speed up your development cycle" → Delegation 섹션에서 IaC 자동화 제안
  - "Services, not servers" → 타겟 서비스 추천 근거
  - "Anticipate and handle errors" → Tradeoff Dossier 리스크 섹션

---

## 5. 출력 리포트 스키마

```markdown
# Serverless Migration Plan — {workload-name}

**생성 일시**: YYYY-MM-DD HH:MM
**분류**: Tier {1|2|3} / {sub-type}
**검증 사례 참조**: {autoresearch | openclaw | 없음}

## Executive Summary

| 항목 | AS-IS (현재) | TO-BE (타겟) | 변화 |
|------|--------------|--------------|------|
| 월간 비용 | $X | $Y | -Z% |
| 관리 오버헤드 | … | 0 | … |
| 콜드 스타트 p99 | 0ms | Xs | 신규 리스크 |
| Spot 인터럽트 리스크 | N/A | X% 예상 | 신규 리스크 |
| 규정 준수 | … | … | … |

## Workload Classification
- 타입, 실행 빈도, 지속 시간, 트래픽 패턴 요약.

## Target Architecture
- Primary: {서비스}
- Alternatives: {서비스}
- 선택 근거: [AWS Docs §…], [Insight #N]

## Tradeoff Dossier

| 리스크 | 근거 | 완화 전략 |
|--------|------|-----------|
| Spot 인터럽트 | [AWS Docs: Spot Interruptions] | `max_wait`, 체크포인트 |
| 콜드 스타트 p99 | [Lambda Quotas] | Provisioned Concurrency |
| … | … | … |

## Staged Migration Checklist

- [ ] **Stage 0 — 사전 준비**
  - [ ] 서비스 쿼터 확인 / 증액 요청
  - [ ] Spot placement score 조사 (배치 워크로드만)
  - [ ] IAM 역할 최소 권한 정의
- [ ] **Stage 1 — 저위험 검증**
  - [ ] 데이터 샘플로 dry-run
  - [ ] 비용 측정
- [ ] **Stage 2 — 파일럿 이행**
  - [ ] 트래픽 X% 분기
  - [ ] 관측·알람 구축
- [ ] **Stage 3 — 전환**
  - [ ] DNS/로드밸런서 절체
  - [ ] 이전 리소스 폐기

## Delegation

> 타겟이 **SageMaker Managed Spot**으로 확정되었습니다.
> 세부 구현은 `sagemaker-spot-training` 스킬로 이어 진행해주세요.

## Citations

- AWS Docs: Lambda Quotas — §Function config
- AWS Docs: SageMaker Managed Spot Training
- AWS Docs: Fargate Capacity Providers
- AWS Docs: EC2 Spot Interruptions
- AWS Docs: AWS Batch with Spot
- AWS Well-Architected Serverless Lens (2022-07-14)
- Source Project Insight #1, #5, #13 (`source-insights.md`)
- 검증 사례: `case-study-{autoresearch|openclaw}.md`
```

---

## 6. 인터뷰 시스템 상세

### 6.1 원칙

- **질문당 2-4 옵션** + 자동 "기타".
- **단계별 분기**: Phase 1 응답에 따라 Phase 3 질문 집합이 달라짐 (interview-bank.md).
- **Why/How 설명**: 트레이드오프 질문에는 description에 "왜 이 질문이 중요한지" 기재.

### 6.2 예시 (Phase 3, Tier 2 API 선택 시)

```
Q: 콜드 스타트 p99 허용 한도는?
  1. <500ms — Provisioned Concurrency + warm-up 필요
  2. <2s — Lambda 기본 (Node/Python) 충족 가능
  3. <5s — Lambda 컨테이너 (Java/대형 의존성) 허용
  4. 허용 — 비용 최적화 우선
```

### 6.3 인터뷰 스킵 조건

- IaC 파일에서 핵심 정보가 추출 가능하고 사용자가 "기본값 사용"을 선택한 경우.

---

## 7. Delegation 및 스킬 간 호출

### 7.1 원칙

본 스킬은 **문서화 + 의사결정**까지. 구현 how-to는 다음 스킬로 위임:

| 타겟 확정 서비스 | 위임 스킬 | 상태 |
|-----------------|-----------|------|
| SageMaker Managed Spot Training | `sagemaker-spot-training` | 존재 |
| AWS Lambda | (향후 `lambda-deployment`) | 미존재 |
| AWS Batch | (향후 `aws-batch-workflow`) | 미존재 |
| ECS Fargate / Fargate Spot | (향후 `fargate-service`) | 미존재 |

미존재 스킬로 위임 시: 리포트 "Delegation" 섹션에 "이 단계는 아직 전용 스킬이 없습니다. [링크된 AWS Docs]를 참고하세요." 표기.

### 7.2 컨텍스트 핸드오프

리포트 파일(`docs/serverless-migration/{date}-{topic}.md`)이 다음 세션의 컨텍스트 소스가 됨. 위임 스킬은 해당 파일을 읽어 Phase 4-5의 결정사항을 승계.

---

## 8. 검증 사례 인용 규칙

### 8.1 두 검증 사례

| 사례 | 티어 | 핵심 숫자 | 참조 파일 |
|------|------|-----------|-----------|
| serverless-autoresearch | Tier 1 | 48실험 $3.94, H100 229s $0.16 vs 상용 $7~24/8h | `case-study-autoresearch.md` |
| serverless-openclaw | Tier 2 | ~$1/월, Lambda 1.35s 콜드 스타트, Fargate Spot fallback | `case-study-openclaw.md` |

### 8.2 인용 라벨

- `[AWS Docs]` — AWS 공식 문서 출처
- `[Insight #N]` — source-insights.md의 번호화 항목
- `[Case: autoresearch/openclaw]` — 사례 근거

세 라벨은 리포트·SKILL.md 본문·references 전체에 일관 적용.

---

## 9. Tier 3 취급 방침

HANDOFF는 Tier 3를 out-of-scope로 제안했으나 사용자 결정으로 **동등 취급**.
단 실 검증 사례가 없으므로:

1. **원칙 수준 패턴만 제시**: Strangler Fig, Branch by Abstraction, CDC (Change Data Capture) 기반 이전.
2. **공식문서 링크로 상세 회피**: 스킬은 의사결정 질문과 AWS 공식 가이드 URL 제공까지.
3. **리스크 경고 명시**: 리포트 상단에 "Tier 3는 검증 사례 없음 — 파일럿 필수" 주의.

---

## 10. 산출물 목록

| 파일 | 설명 |
|------|------|
| `plugins/workflow/skills/serverless-migration-advisor/SKILL.md` | 메인 스킬 (500줄 이하) |
| `plugins/workflow/skills/serverless-migration-advisor/references/*.md` | 13개 참조 파일 |
| `plugins/workflow/.claude-plugin/plugin.json` | (기존) workflow 플러그인 메타데이터 |
| `.claude-plugin/marketplace.json` | `workflow` 항목 `skills` 배열에 본 스킬 추가 |
| `README.md` | Workflow 카테고리 테이블에 본 스킬 추가 |
| `docs/serverless-migration/` | 런타임 리포트 저장소 (사용 시 생성) |

---

## 11. 비목표(Non-Goals)

HANDOFF §6 계승:

- **실시간 AWS 요금 계산 아님** — 실험 기반 범위만 인용.
- **Terraform 생성기 아님** — 스니펫·diff 제안까지.
- **멀티클라우드 아님** — AWS 전용.
- **침묵 금지** — 실패 모드(CUDA 오류, 쿼터 지연, FA3 호환성 등) 반드시 노출.
- **구현 how-to 아님** — 타 스킬로 위임.

---

## 12. 성공 기준 (HANDOFF §7 매핑)

사용자가 "야간 배치 작업을 EC2 H100에서 돌리는데 월 $N 비용 — 싸게 하고 싶다"고 시작했을 때 **한 번의 대화**에서:

1. ✅ 워크로드 분류 (Phase 1)
2. ✅ 타겟 서버리스 패턴 식별 (Phase 4 매핑)
3. ✅ 비용 절감 범위 추정 (검증 사례 인용)
4. ✅ Top-3 리스크 플래그 (Tradeoff Dossier)
5. ✅ 단계별 체크리스트 (Staged Migration Checklist)
6. ✅ Insight #N / AWS Docs 인용 — traceable

**보조 지표**: IaC 제공 시 diff-style 제안 가능 (Phase 2).

---

## 13. 인터뷰 요약 (설계 결정)

| 항목 | 결정 |
|------|------|
| 스킬 구조 | 단일 오케스트레이터 |
| sagemaker-spot-training 관계 | Upstream advisor + delegation |
| 카테고리 | workflow/ |
| 범위 | Tier 1 + Tier 2 + Tier 3 (Tier 3는 원칙 수준) |
| 인터뷰 방식 | 단계별 AskUserQuestion, 5 Phase |
| 출력 형식 | 테이블형 리포트 + 단계별 체크리스트 |
| AWS 문서 참조 | Serverless Lens 포함 폭넓게 |
| 인용 라벨 | `[AWS Docs]` / `[Insight #N]` / `[Case: …]` |
| 검증 사례 | autoresearch + openclaw |
| 런타임 AWS 호출 | 기본 OFF (요청 시만) |
| 중복 관리 | aws-well-architected 스킬과 역할 분리 (리뷰 vs 이행) |

---

## 14. 오픈 질문 (구현 단계에서 결정)

- **IaC 파서**: Terraform HCL 파싱은 tree-sitter? 간단한 정규식? 첫 버전은 정규식으로 필드 추출, 한계 명시.
- **리포트 파일명 충돌**: 같은 날 여러 마이그레이션 계획 시 슬러그 중복 방지 규칙 (`-2`, `-3` 접미사).
- **검증 사례 업데이트**: autoresearch / openclaw 커밋 해시 기록, 6개월마다 리뷰 권고.
- **Serverless Lens 버전 추적**: 현재 2022-07-14. AWS 개정 시 `references/serverless-lens.md` 스냅샷 날짜 갱신.

---

*설계 기준 일자: 2026-04-18.*
*근거 HANDOFF: `issues/3-serverless-migration/HANDOFF.md` (serverless-autoresearch commit 5435b37).*
