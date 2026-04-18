> **Snapshot date**: 2026-04-18
> **Source**: github.com/serithemage/serverless-openclaw (alpha)
> **Tier**: 2 (상시형 API)
> **Description**: Tier 2 검증 사례 — serverless-openclaw

# Case Study — serverless-openclaw

본 케이스는 본 스킬의 **Tier 2 (상시형 API) 인용 앵커**다. 리포트 Tradeoff Dossier, 월 비용 추정, Lambda+Fargate 이중 구성 근거는 이 파일과 [source-insights.md](source-insights.md) #O1-#O6로 역추적된다.

## Headline 숫자

- **월 비용 목표 $1-2** (Free Tier 시 $0.23) — zero-idle 모든 구성요소의 총합
- **Lambda Container cold start 1.35초** (warm 0.12초)
- **ECS Fargate Spot fallback → 컴퓨트 비용 70% 절감**
- **API Gateway 채택으로 ALB 고정비 $18-25/월 제거**
- **EventBridge scheduled pre-warming** → 액티브 시간대 **0초 first-response** (월 ~$0.07)
- **Primary: Lambda Container / Fallback: ECS Fargate Spot** — Lambda 15분 상한 초과 세션만 Fargate로

## 목표 워크로드

- **OpenClaw AI agent 온디맨드 실행** — LLM 기반 대화 에이전트
- **Web UI (React SPA) + Telegram bot 이중 인터페이스** — 두 경로에서 동일 세션
- **멀티 LLM 지원**: Claude / GPT / DeepSeek — 모델 키만 교체
- **개인·사이드 프로젝트 수준 트래픽** — 일 수십~수백 요청

## 아키텍처 요약

```text
User (Web or Telegram)
        │
        ▼
   API Gateway
        │
        ▼
   Lambda Container (primary, zero-idle)
     ├─ ECS Fargate Spot (fallback when 긴 세션 >15분)
     ├─ S3 (session persistence, web assets via CloudFront)
     ├─ DynamoDB (session index)
     └─ EventBridge (active hours pre-warming)
```

핵심 구성 요소:

- **API Gateway**: pay-per-request 모델. ALB 고정비($18-25/월) 제거의 핵심.
- **Lambda Container**: Primary compute. Python + 대형 의존성(LLM SDK)을 컨테이너 이미지로 패키징. Cold start 1.35초 수용.
- **ECS Fargate Spot**: Fallback compute. Lambda 15분·6MB 페이로드 한계 초과 시에만 호출. 70% 비용 절감.
- **DynamoDB**: 세션 인덱스·메타데이터. On-Demand 모드로 zero-idle.
- **S3**: 세션 payload·대화 이력·웹 SPA 에셋. CloudFront로 배포.
- **EventBridge Scheduler**: 액티브 시간대만 Lambda 주기 호출 (월 ~$0.07). 24/7 Provisioned Concurrency의 비용 회피.
- **CloudFront**: 웹 UI 정적 호스팅 (S3 origin). EC2/Lambda 없이 UI 서빙.

## 인용 가능 범위 (Quotable statements)

각 항목은 리포트 Target Architecture, Tradeoff Dossier, Executive Summary 칸에 **직접 인용** 가능:

- "ALB를 API Gateway로 교체하면 상시형 API의 고정비 **$18-25/월**이 제거됨 — [Case: openclaw + Insight #O2]"
- "Lambda Container cold start는 **1.35초** 수준 — Provisioned Concurrency 없이도 대화형 UX 수용 가능 — [Case: openclaw]"
- "Lambda primary + Fargate Spot fallback 이중 구성으로 요청당 비용 **70% 절감** (긴 세션만 Fargate) — [Insight #O1]"
- "EventBridge로 액티브 시간만 pre-warming 시 **0초 first-response** 달성, 월 ~$0.07 추가 — [Insight #O3]"
- "상태 없는 Lambda에서 **S3/DynamoDB 세션 영속화**로 대화 지속성 확보 — [Insight #O4]"
- "정적 웹 UI는 **CloudFront + S3**로 서버 런타임 없이 서빙 → 0 idle 비용 — [Insight #O6]"
- "Free Tier 내 월 **$0.23**, Free Tier 소진 후 **$1-2/월** 수준 — 개인·사이드 프로젝트 비용 타겟 근거 — [Insight #O5]"

## 적용 가능 워크로드

- **상시형 REST/GraphQL API** (요청당 <15분, 동기 페이로드 <6MB)
- **WebSocket chat** (API Gateway WebSocket + Lambda) — 메시지 단위 처리
- **Free Tier 예산 ~$1 타겟** 개인·사이드 프로젝트
- **정적 웹 UI** (S3 + CloudFront) — Next.js export / React SPA
- **이중 인터페이스** (Web + 메신저 봇 동시 운영)
- **저트래픽·버스트 패턴** (idle → spike → idle 반복)

## 적용 불가

- **대규모 트래픽 상시 피크** — Lambda 동시성 기본 1,000 한계 [tradeoffs-compute.md §1.1]
- **지속 연결 수초 이상** — Lambda 15분 상한 초과 시 Fargate 불가피 [AWS Docs]
- **초저지연 API p99 <100ms** — cold start 1.35초가 리스크. Provisioned Concurrency 또는 SnapStart(Java/Python 3.12+) 고려
- **대용량 동기 응답 >6MB** — Lambda 동기 페이로드 한계. 스트리밍(200MB) 또는 S3 presigned URL로 우회
- **엄격한 SLA 요구 프로덕션** — Spot 기반 Fargate fallback은 SLA 엄격 워크로드 부적합 [AWS Docs — Batch Spot]

## 비용 설계 원칙 (Tier 2 특화)

- **Zero-idle + per-request 청구** 모든 구성요소에 적용 [Insight #O5]
- **static vs dynamic 경로 분리** — 정적 UI는 CloudFront+S3, 동적 요청만 Lambda [Insight #O6]
- **Pre-warming 비용 < Provisioned Concurrency 비용** — EventBridge $0.07/월 vs PC $15~/월 [Insight #O3]
- **Lambda Container 선택의 대가**: SnapStart 미지원. Java 스택이라면 SnapStart + zip 배포 재고려 [RESEARCH §13]

## Cross-references (내부)

- [patterns-tier2-api.md](patterns-tier2-api.md) Pattern 2.1 (API Gateway + Lambda), Pattern 2.2 (Fargate Spot fallback), Pattern 2.3 (세션 영속화)
- [tradeoffs-compute.md](tradeoffs-compute.md) §1 (Lambda), §3 (Fargate + Fargate Spot)
- [tradeoffs-data-layer.md](tradeoffs-data-layer.md) §2 (DynamoDB On-Demand)
- [tradeoffs-event-driven.md](tradeoffs-event-driven.md) (EventBridge Scheduler)
- [source-insights.md](source-insights.md) #O1-#O6 — 번호화된 인사이트
