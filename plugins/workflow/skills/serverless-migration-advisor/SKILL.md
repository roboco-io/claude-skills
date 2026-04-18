---
name: serverless-migration-advisor
description: AWS always-on 아키텍처(EC2/ALB/ECS/RDS)를 서버리스+Spot 패턴으로 이행할 때 사용. 워크로드 분류, 트레이드오프 평가, 단계별 이행 계획 생성. 구현 how-to는 sagemaker-spot-training 등 후속 스킬로 위임. 트리거 예 - "서버리스 이행", "EC2에서 Lambda로", "Spot 이행", "serverless migration", "ALB에서 API Gateway", "비용 절감 이행".
---

# Serverless Migration Advisor

**Role:** 기존 AWS 워크로드(EC2/ALB/ECS/RDS/모놀리스)를 서버리스+Spot 패턴으로 이행할 때의 **업스트림 어드바이저**. 워크로드 분류 → 트레이드오프 평가 → 타겟 아키텍처 매핑 → 단계별 이행 계획 생성을 담당한다. 구현 how-to는 후속 스킬로 **위임**한다.

## 이 스킬이 아닌 것

- `aws-well-architected`: 기존 아키텍처의 **Pillar 준수 리뷰** — 본 스킬은 **이행**에 집중한다.
- 실시간 AWS 요금 계산기 아님. **검증 사례** 기반의 비용 범위만 인용한다.
- Terraform/CDK 생성기 아님. 스니펫과 **체크리스트**까지만 제공한다.
- 멀티클라우드 아님. AWS 전용이다.
- 구현 how-to 아님. 타겟 확정 후 `sagemaker-spot-training` 등으로 **위임**한다.

## 언제 사용하나

트리거 키워드: 서버리스 이행, EC2에서 Lambda로, Spot 이행, ALB에서 API Gateway, 월 비용 절감 이행, serverless migration, batch on Spot, 콜드 스타트 이행.

---

## 실행 순서 (5 Phase)

### Phase 1 — Workload Classification (항상 실행)

[interview-bank.md](references/interview-bank.md) §Phase 1의 Q1-Q4 JSON을 AskUserQuestion으로 순차 호출한다:

- Q1 Workload type: 배치/훈련 / 상시 API / ETL / 이벤트 기반 / 모놀리스(Tier 3)
- Q2 Current environment
- Q3 Execution frequency
- Q4 Single run duration

응답으로 **Tier(1/2/3)** + **sub-type**을 결정한다. 예: `Tier 1 / ML training / daily / 8h`.

**Tier 3** 응답이 하나라도 있으면 즉시 Branch E 안내문을 표시한다:

> ⚠️ Tier 3 이행은 **검증 사례 없음**. 원칙 수준 가이드와 AWS 공식 링크만 제공됩니다. 파일럿 필수. [patterns-tier3-monolith.md](references/patterns-tier3-monolith.md) 및 [patterns-tier3-data.md](references/patterns-tier3-data.md) 참조.

### Phase 2 — IaC Scan (선택)

사용자가 IaC 파일 경로(Terraform `.tf`, CDK `.ts/.py`, CloudFormation `.yaml`)를 제공하면:

1. Glob으로 파일 목록 획득
2. Read + 정규식 기반 리소스 추출 (첫 버전 한계: `resource "aws_..."`, CDK L2 construct 이름 패턴)
3. 현 아키텍처 요약 테이블 생성 (인스턴스 타입·개수·월 비용 추정 범위)

IaC가 없거나 사용자가 스킵을 선택하면 Phase 3로 넘어간다.

> **IaC 파서 한계**: 정규식 기반은 참조 추출만 지원한다. 상호 참조·변수 치환·module 재귀는 미지원이다. 깊은 분석이 필요하면 수동 입력을 요청한다.

### Phase 3 — 제약·리스크 심층 인터뷰

Phase 1 Q1 응답에 따라 [interview-bank.md](references/interview-bank.md) §Phase 3의 분기 중 하나를 실행한다:

- **Branch A (Batch/Training)**: A1 Spot 허용도 / A2 wall-clock / A3 체크포인트
- **Branch B (Always-on API)**: B1 콜드 스타트 p99 / B2 지속 연결 / B3 트래픽 패턴
- **Branch C (ETL)**: C1 데이터 볼륨 / C2 지속 시간 / C3 상태 저장소
- **Branch D (Event-driven)**: D1 이벤트 소스(multiSelect) / D2 순서 보장 / D3 중복 허용
- **Branch E (Monolith / Tier 3)**: E1 bounded context 식별 단계 / E2 다운타임 / E3 데이터 일관성

공통 follow-ups(모든 branch): C_Cost 월 예산 / C_Compliance 규정 / C_RTORPO.

### Phase 4 — Target Architecture Mapping

인터뷰 결과 + IaC 스캔(있으면)을 [patterns-tier{1|2|3}-*.md](references/)와 매핑한다:

| Classification | Primary | Secondary | Delegation |
|---------------|---------|-----------|------------|
| Tier 1 / ML training / 체크포인트 가능 | SageMaker Managed Spot | AWS Batch + Spot | `sagemaker-spot-training` 존재 |
| Tier 1 / ETL (<15min) | Lambda + S3 + EventBridge | - | 없음 (AWS Docs) |
| Tier 1 / ETL (>15min) | AWS Batch + Spot (Fargate/EC2) | Step Functions + Lambda 분해 | 없음 |
| Tier 2 / API (low cold-start OK) | API Gateway + Lambda | API Gateway + Fargate Spot | 없음 |
| Tier 2 / API (p99 <500ms 요구) | Lambda + Provisioned Concurrency / SnapStart | Fargate (On-Demand baseline) | 없음 |
| Tier 2 / WebSocket | API Gateway WebSocket + Lambda | ALB + Fargate | 없음 |
| Tier 2 / Java monolith | Lambda + SnapStart | Fargate (hybrid) | 없음 |
| Tier 3 / monolith | Strangler Fig + API Gateway routing | - | 없음 (원칙만) |
| Tier 3 / RDS→Aurora v2 | Aurora Serverless v2 (동일 엔진) | - | 없음 |
| Tier 3 / RDS→DynamoDB | DynamoDB + DMS CDC | 원래 RDS 유지 권고 | 없음 (고위험) |

각 매핑 추천 시 **의무**:

1. [patterns-tier{N}-*.md](references/)에서 해당 패턴 상세를 로드한다.
2. [tradeoffs-{compute|spot|data-layer|event-driven}.md](references/)에서 리스크·제약을 확인한다.
3. [case-study-*.md](references/)에서 수치 범위를 인용한다.

### Phase 5 — Report Generation

`docs/serverless-migration/YYYY-MM-DD-{topic-slug}.md` 파일을 생성한다. 슬러그 중복 시 `-2`, `-3` 접미사를 붙인다. 사용자가 리포트 디렉토리를 커스텀하면 그 경로를 사용한다.

리포트 스키마 (SPEC §5 기반):

```markdown
# Serverless Migration Plan — {workload-name}

**생성 일시**: YYYY-MM-DD HH:MM
**분류**: Tier {1|2|3} / {sub-type}
**검증 사례 참조**: {autoresearch | openclaw | 없음}

## Executive Summary
| 항목 | AS-IS | TO-BE | 변화 |
|------|-------|-------|------|
| 월간 비용 | $X | $Y | -Z% |
| 관리 오버헤드 | … | … | … |
| 콜드 스타트 p99 | … | … | … |
| Spot 인터럽트 리스크 | … | … | … |

## Workload Classification
(Phase 1 응답 요약)

## Target Architecture
- Primary: {서비스}
- Alternative: {서비스}
- 근거: [AWS Docs §…], [Insight #N], [Case: …]

## Tradeoff Dossier
| 리스크 | 근거 | 완화 전략 |
|--------|------|-----------|
(Phase 4 매핑에서 나온 tradeoff 3-5개)

## Staged Migration Checklist
- [ ] Stage 0 — 사전 준비 (쿼터, placement scores, IAM)
- [ ] Stage 1 — 저위험 검증 (cheap Spot, 샘플 데이터)
- [ ] Stage 2 — 파일럿 (부분 트래픽, 관측 구축)
- [ ] Stage 3 — 전환 (DNS/LB 절체, 이전 리소스 폐기)

## Delegation
> 타겟이 **{service}**로 확정되었습니다.
> 세부 구현은 `{next-skill-name}` 스킬로 이어 진행해주세요. (없으면 AWS Docs URL 제공)

## Citations
- [AWS Docs — …](URL) × N
- [Insight #N] × N
- [Case: {autoresearch|openclaw}]
```

---

## Citation Label 규칙 (의무)

모든 트레이드오프 주장·추천 근거에는 최소 하나의 라벨이 있어야 한다:

- **[AWS Docs]** — AWS 공식 문서 출처 (URL 동반)
- **[Insight #N]** — [source-insights.md](references/source-insights.md)의 항목 (N은 1-15 또는 O1-O6)
- **[Case: autoresearch|openclaw]** — 검증 사례

라벨 없는 주장은 **질문으로 전환**하거나 삭제한다. 리포트 하단 Citations 섹션에 모든 라벨을 수집한다.

---

## Delegation Map

| 타겟 서비스 | 위임 스킬 | 상태 |
|-----------|----------|------|
| SageMaker Managed Spot Training | `sagemaker-spot-training` | 존재 (`plugins/development/skills/`) |
| AWS Lambda | (향후 `lambda-deployment`) | 미존재 — AWS Docs 링크 제공 |
| AWS Batch | (향후 `aws-batch-workflow`) | 미존재 |
| ECS Fargate / Fargate Spot | (향후 `fargate-service`) | 미존재 |

미존재 스킬로 위임하는 경우 리포트 Delegation 섹션에 "이 단계는 아직 전용 스킬이 없습니다. [AWS Docs: {URL}] 참조"를 명시한다.

---

## Tier 3 주의 (반복 강조)

Tier 3는 **검증 사례가 없다**. [patterns-tier3-monolith.md](references/patterns-tier3-monolith.md) / [patterns-tier3-data.md](references/patterns-tier3-data.md) 상단 경고를 리포트 Executive Summary 바로 아래에 복제한다:

> ⚠️ **Tier 3 이행 경고**: 본 조언은 AWS 공식 patterns + 원칙 수준 가이드 기반이며, 동등한 규모의 검증된 레퍼런스 구현이 없다. **1-2개 bounded context로 파일럿 필수**.

---

## 설정 파일 (선택)

프로젝트 루트에 `.serverless-migration.yaml`이 존재하면 기본값으로 사용한다 (없으면 인터뷰에서 결정):

```yaml
default_region: us-west-2
report_dir: docs/serverless-migration/
language: ko  # 또는 en
include_iac_scan: true  # false면 Phase 2 스킵
```

---

## 오류 모드 노출 (의무 — SPEC §11 Non-goal "침묵 금지")

리포트 Tradeoff Dossier 또는 Citations에 반드시 다음을 언급한다:

- CUDA / FA3 GPU arch 호환성 — `[Insight #4, #13]`
- Spot 쿼터 지연 (H100/B200은 days) — `[Insight from spot-capacity-guide]`
- Cold start 신규 리스크 — `[AWS Docs — Lambda quotas]`, `[Case: openclaw]` (1.35s baseline)
- Fargate Spot 단일 태스크 가용성 위험 — `[AWS Docs — Fargate capacity providers]`
- SnapStart 제약 (런타임 한정, 비결정 초기화) — `[AWS Docs — Lambda SnapStart]`
- 최대가 지정 안티패턴 (Spot 인터럽트 빈도 증가) — `[AWS Docs — Spot interruptions]`

---

## References (Progressive Disclosure)

- [tradeoffs-compute.md](references/tradeoffs-compute.md) — Lambda / SageMaker / Fargate / EC2 Spot / Batch 공식 트레이드오프
- [tradeoffs-spot.md](references/tradeoffs-spot.md) — 인터럽트, placement scores, HUGI, billable 정의
- [tradeoffs-data-layer.md](references/tradeoffs-data-layer.md) — RDS / Aurora Serverless v2 / DynamoDB / S3 Express
- [tradeoffs-event-driven.md](references/tradeoffs-event-driven.md) — EventBridge / SQS / Kinesis / Step Functions
- [serverless-lens.md](references/serverless-lens.md) — AWS WA Serverless Lens 원칙 매핑
- [patterns-tier1-batch.md](references/patterns-tier1-batch.md) — 배치·훈련·ETL 이행 패턴
- [patterns-tier2-api.md](references/patterns-tier2-api.md) — 상시형 API·웹 이행 패턴
- [patterns-tier3-monolith.md](references/patterns-tier3-monolith.md) — Strangler Fig (검증 없음)
- [patterns-tier3-data.md](references/patterns-tier3-data.md) — RDS→DynamoDB (검증 없음)
- [interview-bank.md](references/interview-bank.md) — Phase별 AskUserQuestion 템플릿
- [case-study-autoresearch.md](references/case-study-autoresearch.md) — Tier 1 검증 ($3.94 / 48실험)
- [case-study-openclaw.md](references/case-study-openclaw.md) — Tier 2 검증 ($1/월)
- [source-insights.md](references/source-insights.md) — 번호화된 Insight #N 인용 앵커

---

## 종료 기준

리포트가 SPEC §12의 6개 성공 기준을 **모두** 충족하면 종료한다:

1. Workload classified (Phase 1)
2. Target serverless pattern identified (Phase 4)
3. 비용 절감 범위 추정 (case study 인용)
4. Top-3 리스크 flagged (Tradeoff Dossier)
5. Staged Migration Checklist 생성
6. Insight #N / AWS Docs 인용 — traceable
