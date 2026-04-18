> **Snapshot date**: 2026-04-18
> **Description**: EventBridge / SQS / Kinesis / Step Functions

# Event-Driven Tradeoffs

이벤트 드리븐 이행의 4대 빌딩블록. 각 서비스의 AWS 공식 한계와 이행 관점의 선택 근거를 정리.

## 1. Amazon EventBridge

Primary citation: [AWS Docs — EventBridge overview](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-what-is.html)
보조: [AWS Docs — EventBridge rules](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rules.html)

### 1.1 핵심 개념

| 개념 | 설명 | 출처 |
|------|------|------|
| Event bus | 이벤트 라우터. default / custom / partner 3종 | [AWS Docs] |
| Pipes | 1:1 point-to-point 통합. source → (filter → enrich → transform) → target | [AWS Docs] |
| Scheduler | 서버리스 cron/rate/one-time 스케줄러 — 레거시 scheduled rules의 후계 | [AWS Docs] |
| Rule | event pattern 매칭 또는 스케줄 기반. **룰당 타겟 최대 5개**, 베스트프랙티스는 **1 룰 = 1 타겟** | [AWS Docs] |
| Event pattern | JSON 기반 content filtering, schema registry 지원 | [AWS Docs] |
| Input transformation | Matched event / part-of-event / constant JSON / input transformer 4종 | [AWS Docs] |

### 1.2 신뢰성·운영

| 항목 | 값 | 출처 |
|------|-----|------|
| 재시도 기본 이벤트 보존 기간 | 24시간 | [AWS Docs] |
| 재시도 기본 횟수 | 최대 185회 | [AWS Docs] |
| Dead-letter queue | SQS Standard 큐 지원 (동일 계정 / 다른 계정 모두 가능) | [AWS Docs] |
| 지연 메트릭 | `IngestionToInvocationStartLatency` — 30초 초과 시 throttle 의심 | [AWS Docs] |
| Throttle 메트릭 | `ThrottledRules` — 계정 aggregate TPS 초과 시 발생 | [AWS Docs] |

### 1.3 이행 관점 함의

- **1 룰 = 1 타겟 원칙** — 타겟 다양화 시 룰 복제가 유지보수에 유리 (BP 문서 명시). [AWS Docs]
- **Content-based filtering**으로 Lambda 함수 레벨의 if/else 분기를 인프라 레이어로 밀어낼 수 있음 — 콜드 스타트·동시성 비용 절감. [AWS Docs]
- **DLQ는 SQS Standard만 지원** — FIFO DLQ 불가. 순서 중요 이벤트는 EventBridge + SQS FIFO가 아닌 SQS FIFO 직접 연결 검토.
- **Scheduler ≠ Scheduled rules** — 신규 설계는 Scheduler가 공식 권고. 레거시 cron 룰은 단계적 이전. [AWS Docs]
- **Pipes vs Rules**: 점대점 enrichment가 필요하면 Pipes, 팬아웃은 Rule + 다중 타겟. [AWS Docs]

## 2. SQS Standard vs FIFO

Primary citation: [AWS Docs — SQS queue types](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-queue-types.html)

### 2.1 비교

| 항목 | Standard | FIFO | 출처 |
|------|----------|------|------|
| 처리량 | **사실상 무제한** TPS per API | 배칭 시 **3,000 msg/s** per API (300 API calls × 10 msg/batch); 배칭 없이 300 API calls/s per API | [AWS Docs] |
| 고처리량 모드 | — | **30,000 TPS** (메시지 그룹 내 순서 완화) | [AWS Docs] |
| 순서 보장 | Best-effort (순서 미보장 가능) | **메시지 그룹 내 FIFO** | [AWS Docs] |
| 전달 시맨틱 | **At-least-once** (중복 가능) | **Exactly-once processing** (dedup 지원) | [AWS Docs] |
| Dedup 창 | — | 5분 (content-based dedup 옵션) | [AWS Docs] |
| 내구성 | 다중 AZ 복제 | 다중 AZ 복제 | [AWS Docs] |
| Visibility timeout | 지원 | 지원 | [AWS Docs] |

### 2.2 이행 관점 함의

- **기본은 Standard** — 순서·중복 처리 불요 시. Lambda consumer의 멱등 설계로 중복 흡수. [AWS Docs]
- **FIFO 선택 조건**: 순서 중요(예: 트랜잭션 로그) OR 정확히 한 번 처리(예: 결제). 처리량 한도 검토 필수. [AWS Docs]
- **High-throughput FIFO 모드**는 메시지 그룹 단위 순서만 유지 — 그룹 수를 늘려 병렬 처리 + 그룹 내 순서 유지 패턴. [AWS Docs]
- **SnsToSqs fan-out**: SNS → 복수 SQS 큐 조합은 여전히 유효하나, EventBridge rule + 다중 타겟으로 대체 권장 (content filtering 병행 가능). [AWS Docs]

## 3. Amazon Kinesis Data Streams

Primary citation: [AWS Docs — Kinesis Data Streams introduction](https://docs.aws.amazon.com/streams/latest/dev/introduction.html)
보조: [AWS Docs — Kinesis quotas](https://docs.aws.amazon.com/streams/latest/dev/service-sizes-and-limits.html)

### 3.1 정량

| 항목 | 값 | 출처 |
|------|-----|------|
| 쓰기 (provisioned shard) | **1 MB/s 또는 1,000 records/s** per shard | [AWS Docs] |
| 읽기 (provisioned shard) | **2 MB/s** per shard, `GetRecords` 최대 5 TPS per shard | [AWS Docs] |
| 페이로드 최대 | **10 MiB** per record (base64 인코딩 전) | [AWS Docs] |
| PutRecords batch | 최대 500 records, 총 10 MiB per request | [AWS Docs] |
| Retention | 기본 **24시간**, 최대 **8,760시간 (365일)** | [AWS Docs] |
| put-to-get 지연 | 일반적으로 1초 미만 | [AWS Docs] |
| On-demand 기본 처리량 | 신규 스트림 4 MB/s 쓰기 / 8 MB/s 읽기 | [AWS Docs] |
| On-demand 최대 (us-east-1/us-west-2/eu-west-1) | **10 GB/s 쓰기 / 20 GB/s 읽기** (증가 요청 가능) | [AWS Docs] |
| On-demand 최대 (기타 리전) | 200 MB/s 쓰기 / 400 MB/s 읽기 | [AWS Docs] |
| On-demand stream 기본 쿼터 | 계정당 **50개** (증가 가능) | [AWS Docs] |
| Enhanced fan-out consumers | 스트림당 최대 **20** (On-demand Advantage: 50) — 각 consumer **2 MB/s** 전용 대역폭 | [AWS Docs] |
| 모드 전환 | 스트림당 24시간에 2회 (on-demand ↔ provisioned) | [AWS Docs] |
| 최소 retention | 24시간 (DecreaseStreamRetentionPeriod 불가) | [AWS Docs] |

### 3.2 이행 관점 함의

- **Shard는 순서의 경계** — shard 내부는 순서 보장, 간에는 보장 없음. 순서 유지 로직은 partition key 설계로 결정. [AWS Docs]
- **Replay/rewind** 가능 — retention 기간 내 임의 시점부터 재처리. DynamoDB/SQS에는 없는 특성. [AWS Docs]
- **Enhanced fan-out** 은 consumer별 2 MB/s 전용 → 다중 consumer 고처리량 시 표준 consumer의 GetRecords 경합 회피 수단. [AWS Docs]
- **On-demand 모드는 신규 서비스의 기본값** — 트래픽 예측 어려울 때. 단 리전별 최대치 편차 존재. [AWS Docs]
- **Kinesis vs EventBridge**: EB는 event router(비동기 fan-out, filter), Kinesis는 내구성 있는 순서 보장 스트림. 동시 사용도 일반적 (Kinesis → Pipes → EventBridge). [AWS Docs]

## 4. Step Functions — Standard vs Express

Primary citation: [AWS Docs — Standard vs Express](https://docs.aws.amazon.com/step-functions/latest/dg/concepts-standard-vs-express.html)
(상세는 [RESEARCH.md §17](../../../../../issues/3-serverless-migration/RESEARCH.md))

### 4.1 비교

| 항목 | Standard | Async Express | Sync Express | 출처 |
|------|----------|---------------|--------------|------|
| 최대 실행 시간 | **1년** | 5분 | 5분 (콘솔 60s 만료, SDK/CLI 5분) | [AWS Docs] |
| 실행 시맨틱 | **Exactly-once** (상태 영속) | **At-least-once** (중복 가능) | **At-most-once** (재시도 없음) | [AWS Docs] |
| 실행 이력 | API 조회 + 콘솔 시각 디버깅, **90일** (30일 축소 요청 가능) | CloudWatch Logs 활성화 필수 | CloudWatch Logs 활성화 필수 | [AWS Docs] |
| 처리량 | state transition rate (account quota) | 초당 수만~수십만 실행 | account 용량과 분리 (자동 스케일) | [AWS Docs] |
| 청구 | **per state transition** | per execution × duration × memory | per execution × duration × memory | [AWS Docs] |
| 지원 통합 | 모든 서비스 + `.sync`, `.waitForTaskToken` | `.sync`, `.waitForTaskToken` 미지원 | `.sync`, `.waitForTaskToken` 미지원 | [AWS Docs] |
| Distributed Map / Activities | 지원 | 미지원 | 미지원 | [AWS Docs] |
| Idempotency | 동명 재실행 시 자동 idempotent | 자동 관리 없음 | 자동 관리 없음 | [AWS Docs] |

### 4.2 이행 관점 함의

- **Workflow type immutable** — state machine 생성 후 Standard ↔ Express 변경 불가. 설계 초기 결정. [AWS Docs]
- **Tier 1 배치 분해**: 15분 초과 배치는 Standard로 분해. Spot 재시도 로직을 상태기계에 명시하고 exactly-once 보장 활용. [AWS Docs]
- **Tier 2 이벤트 후처리**: Async Express — 짧은 fan-out, API 응답 후처리에 적합하지만 **중복 허용** 전제 (멱등성 필수). [AWS Docs]
- **at-least-once 함정**: Async Express는 중복 실행 가능 → Serverless Lens 원칙 7 (Design for failures and duplicates) 준수 필수. 비멱등 작업(예: 결제)은 Standard. [AWS Docs]

## 5. 선택 가이드

| 요구사항 | 추천 | 근거 |
|----------|------|------|
| 단순 이벤트 라우팅 (AWS 서비스 → 다수 타겟) | EventBridge rule + 다중 타겟 | [AWS Docs §1] |
| 이벤트 enrichment 필요 (source → transform → target) | EventBridge Pipes | [AWS Docs §1.1] |
| 스케줄 기반 작업 (cron/rate/one-time) | EventBridge Scheduler | [AWS Docs §1.1] |
| 엄격한 순서 + 정확히 한 번 메시지 처리 | **SQS FIFO** 또는 Step Functions Standard | [AWS Docs §2] / [AWS Docs §4] |
| 고처리량 대기열 (순서 무관) | SQS Standard | [AWS Docs §2] |
| 고처리량 스트리밍 + replay 필요 | Kinesis Data Streams | [AWS Docs §3] |
| 다중 consumer 저지연 스트리밍 | Kinesis Data Streams + Enhanced Fan-out | [AWS Docs §3.1] |
| 장기 워크플로 (≤1년, 감사 필요) | Step Functions **Standard** | [AWS Docs §4] |
| 고빈도 저비용 워크플로 (≤5분, 멱등 가능) | Step Functions **Express** | [AWS Docs §4] |
| API Gateway 뒤 동기 마이크로서비스 | Step Functions Sync Express (at-most-once 수용 시) | [AWS Docs §4] |

---

*근거 상세*: Step Functions는 RESEARCH §17에서 수집 완료. EventBridge / SQS / Kinesis는 본 Stage C에서 AWS Docs 재수집 (RESEARCH §8.6 이월 항목 해결).
