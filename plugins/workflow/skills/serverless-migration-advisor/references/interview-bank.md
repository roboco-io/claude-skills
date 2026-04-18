> **Snapshot date**: 2026-04-18
> **Description**: Phase별 AskUserQuestion 질문 뱅크

# Interview Bank — AskUserQuestion Templates

SKILL.md의 Phase 1, 3 인터뷰가 호출할 질문 집합. 모든 질문은 AskUserQuestion 도구 규격(JSON)으로 기재. Phase 1은 항상 실행, Phase 3은 Phase 1 응답에 따라 Branch A~E로 분기.

## Phase 1 — Workload Classification (항상 실행)

Phase 1 Q1-Q4는 스킵 불가. 답변에 따라 Phase 3 Branch가 결정된다.

### Q1 — Workload type

```json
{
  "question": "현재 워크로드의 주 타입을 선택해주세요.",
  "header": "워크로드",
  "multiSelect": false,
  "options": [
    { "label": "배치/훈련", "description": "ML 훈련, 대규모 데이터 가공, 주기적 무거운 계산" },
    { "label": "상시 API", "description": "REST/GraphQL/WebSocket 상시 접근 API" },
    { "label": "ETL", "description": "데이터 파이프라인, 변환·적재" },
    { "label": "이벤트 기반", "description": "큐·스트림·웹훅 트리거로 동작" }
  ]
}
```

(기타 옵션은 AskUserQuestion이 자동 제공 — "모놀리스" 선택 시 Tier 3 트랙 Branch E)

### Q2 — Current environment

```json
{
  "question": "현재 실행 환경은?",
  "header": "환경",
  "multiSelect": false,
  "options": [
    { "label": "EC2 24/7", "description": "상시 인스턴스" },
    { "label": "EC2 + Auto Scaling", "description": "수평 확장 구성" },
    { "label": "ECS/EKS", "description": "컨테이너 오케스트레이션" },
    { "label": "EMR/온프레/기타", "description": "Hadoop, on-prem, 외부 클라우드" }
  ]
}
```

### Q3 — Execution frequency

```json
{
  "question": "실행 빈도는?",
  "header": "빈도",
  "multiSelect": false,
  "options": [
    { "label": "상시", "description": "24/7 지속 처리" },
    { "label": "일 수회", "description": "하루에 몇 번 수동/자동 실행" },
    { "label": "일 1회", "description": "야간 배치 등" },
    { "label": "주·월 단위 / 이벤트", "description": "희소 실행" }
  ]
}
```

### Q4 — Single run duration

```json
{
  "question": "단일 작업의 지속 시간은?",
  "header": "지속시간",
  "multiSelect": false,
  "options": [
    { "label": "<1분", "description": "Lambda·Step Functions Express 수용" },
    { "label": "1~15분", "description": "Lambda 상한 이내" },
    { "label": "15분~1시간", "description": "Batch·Fargate·Step Functions Standard" },
    { "label": ">1시간", "description": "배치·훈련 장기 작업" }
  ]
}
```

## Phase 3 — Branches by Phase 1

Phase 1 Q1의 응답으로 분기. 아래 각 Branch는 대표 질문 1개를 전체 JSON으로, 나머지는 minimal schema로 기재.

### Branch A — Batch / Training

트리거: Phase 1 Q1 = "배치/훈련". Tier 1 패턴 적용.

**A1. Spot 인터럽트 허용도**

```json
{
  "question": "Spot 인터럽트를 허용할 수 있나요?",
  "header": "Spot 허용도",
  "multiSelect": false,
  "options": [
    { "label": "허용 (재시도 가능)", "description": "체크포인트 또는 idempotent 재실행 가능" },
    { "label": "제한적 (체크포인트 있음)", "description": "2분 내 정리 가능" },
    { "label": "불가", "description": "연속성 보장 필수 — Spot 대신 On-Demand 권고" }
  ]
}
```

**A2. 최대 허용 wall-clock** (minimal — `<30분` / `<2시간` / `<8시간` / `>8시간` 옵션)

**A3. 체크포인트 구현 여부** (minimal — `없음` / `부분 구현` / `완전 구현` 옵션; SageMaker Managed Spot의 `MaxWaitTime ≤ 3600s` 제약 판단에 활용)

### Branch B — Always-on API

트리거: Phase 1 Q1 = "상시 API". Tier 2 패턴 적용.

**B1. Cold start p99 허용**

```json
{
  "question": "콜드 스타트 p99 허용 한도는?",
  "header": "Cold start",
  "multiSelect": false,
  "options": [
    { "label": "<500ms", "description": "Provisioned Concurrency + warm-up 필요" },
    { "label": "<2s", "description": "Lambda 기본 (Node/Python) 충족 가능" },
    { "label": "<5s", "description": "Lambda 컨테이너 (Java/대형 의존성) 허용" },
    { "label": "허용", "description": "비용 최적화 우선, 간헐적 지연 수용" }
  ]
}
```

**B2. 지속 연결 요구 종류** (minimal — `없음` / `WebSocket` / `SSE` / `gRPC streaming` 옵션; Fargate 필수 여부 판단)

**B3. 트래픽 패턴** (minimal — `상시 평탄` / `스파이키 버스트` / `시간대 패턴` / `예측 불가` 옵션; Provisioned Concurrency vs EventBridge pre-warming [Insight #O3] 선택)

### Branch C — ETL

트리거: Phase 1 Q1 = "ETL". Tier 1 패턴 + 데이터 레이어 질문.

**C1. 데이터 볼륨 per 실행**

```json
{
  "question": "한 번의 ETL 실행 당 처리 볼륨은?",
  "header": "데이터 볼륨",
  "multiSelect": false,
  "options": [
    { "label": "<1 GB", "description": "Lambda + S3 수용" },
    { "label": "1-100 GB", "description": "AWS Batch (Fargate) 권고" },
    { "label": "100 GB-1 TB", "description": "AWS Batch (EC2 Spot) + Glue" },
    { "label": ">1 TB", "description": "EMR on EC2 Spot 또는 Redshift Serverless" }
  ]
}
```

**C2. 작업 지속 시간** (minimal — `<15분` / `15분~1시간` / `1~8시간` / `>8시간` 옵션)

**C3. 상태 저장소** (minimal — `S3 only` / `S3 + RDS/Aurora` / `DynamoDB` / `Redshift/Glue Catalog` 옵션)

### Branch D — Event-driven

트리거: Phase 1 Q1 = "이벤트 기반".

**D1. 이벤트 소스**

```json
{
  "question": "주요 이벤트 소스는?",
  "header": "이벤트 소스",
  "multiSelect": true,
  "options": [
    { "label": "HTTP webhook", "description": "API Gateway → Lambda" },
    { "label": "S3 object PUT", "description": "S3 event → Lambda/SQS" },
    { "label": "DB change", "description": "DynamoDB Streams / RDS CDC via DMS" },
    { "label": "스케줄 기반", "description": "EventBridge Scheduler" }
  ]
}
```

**D2. 순서 보장 요구** (minimal — `필수 (FIFO)` / `best-effort` / `불필요` 옵션; SQS FIFO vs Standard, Kinesis vs EventBridge 선택)

**D3. 중복 허용** (minimal — `멱등` / `at-least-once 허용` / `exactly-once 필수` 옵션; Step Functions Standard vs Express 선택 [RESEARCH §17])

### Branch E — Monolith (Tier 3)

트리거: Phase 1 Q1 = "모놀리스" (기타 옵션).

> ⚠️ Branch E 진입 시, 먼저 다음 문구를 표시:
> "Tier 3 이행은 검증 사례 없음. 원칙 수준 가이드와 AWS 공식 링크만 제공됩니다. 파일럿 필수."

**E1. 서비스 경계 식별 단계**

```json
{
  "question": "Bounded context(서비스 경계) 식별은 어느 정도 진행되었나요?",
  "header": "경계식별",
  "multiSelect": false,
  "options": [
    { "label": "초기 (분석 전)", "description": "도메인 분석부터 필요 — 본 스킬 범위 밖" },
    { "label": "중기 (2-3개 후보)", "description": "파일럿 candidate 선별 가능" },
    { "label": "후기 (분해 계획 존재)", "description": "개별 서비스별 이행 패턴 적용 가능" }
  ]
}
```

**E2. 다운타임 윈도우** (minimal — `무중단 필수` / `주간 몇 분` / `월간 수 시간` / `주말 유지보수 창` 옵션)

**E3. 데이터 일관성 요구** (minimal — `strong consistency` / `eventual 허용` / `per-domain 혼합` 옵션; Strangler Fig 중 데이터 이동 전략 결정 [patterns-tier3-data.md])

## Common follow-ups (모든 Tier에서 질문)

Phase 3 Branch 완료 후, 리포트 Executive Summary 및 Tradeoff Dossier 작성 전에 공통 질문 수행.

### C_Cost. 월 목표 비용

```json
{
  "question": "월간 AWS 비용 목표 범위는?",
  "header": "예산",
  "multiSelect": false,
  "options": [
    { "label": "<$10", "description": "Free Tier + Lambda 중심" },
    { "label": "$10-100", "description": "소규모 상용 서비스" },
    { "label": "$100-1000", "description": "중간 규모 워크로드" },
    { "label": ">$1000", "description": "대규모 — ROI 최적화 중심" }
  ]
}
```

### C_Compliance. 규정 준수

(minimal — `PCI-DSS` / `HIPAA` / `GDPR` / `SOC2` / `없음` 옵션; multiSelect=true 권장. S3 Express One Zone의 단일 AZ, DynamoDB 암호화 선택, VPC 배치 제약 판단에 활용)

### C_RTORPO. RTO/RPO

(자유 입력 권고 — AskUserQuestion의 사전 정의 옵션보다는 텍스트 수집이 적합. 예: "RTO 4시간 / RPO 1시간", "RTO 5분 / RPO 0". 리포트 Tradeoff Dossier의 가용성 섹션에 직접 인용.)

## 인터뷰 스킵 규칙

- **IaC 파일에서 핵심 정보 추출 가능하고 사용자가 "기본값 사용" 선택 시 Phase 3 스킵 가능** (SPEC §6.3). 이 경우 기본값은:
  - Spot 허용도: 체크포인트 있으면 "허용", 없으면 "불가"
  - Cold start p99: <2s (Lambda 기본)
  - 데이터 볼륨: IaC의 컨테이너 메모리·작업 디렉토리로 추정
- **Phase 1 Q1~Q4는 스킵 불가** — classification 근거.
- **Branch E 진입 시 경고 메시지 필수** — 검증 사례 없음을 반드시 노출.
- **C_Compliance에서 PCI-DSS/HIPAA 선택 시** — S3 Express One Zone, Fargate Spot 단일 태스크는 자동 제외 후보로 표시.

## 질문 설계 원칙 (SPEC §6.1)

- **질문당 2-4 옵션** + AskUserQuestion 자동 제공 "기타".
- **description에 Why/How**: 단순 레이블이 아니라 "왜 이 질문이 결정에 중요한지"를 명시.
- **단계별 분기**: Phase 1 응답이 Phase 3 질문 집합을 결정 — 불필요한 질문 방지.
- **트레이드오프 연결**: 각 옵션은 references/의 트레이드오프 표 특정 행과 대응하도록 레이블링.
