# Issue #3: AWS 공식문서 기반 트레이드오프 리서치 스냅샷

> **수집 일자**: 2026-04-18
> **목적**: 스킬의 `references/tradeoffs-*.md` 작성을 위한 1차 소스 집합.
> **원칙**: 스킬은 AWS Docs 원문을 재인용하지 않고, 본 스냅샷 기반으로 요약·함의 작성.

## 1. 수집 대상 및 URL

| 문서 | URL | 상태 |
|------|-----|------|
| AWS Well-Architected Serverless Lens | https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/welcome.html | 1차 완료 (서론만) |
| AWS Lambda quotas | https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html | 완료 |
| ECS Fargate capacity providers | https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-capacity-providers.html | 완료 |
| SageMaker Managed Spot Training | https://docs.aws.amazon.com/sagemaker/latest/dg/model-managed-spot-training.html | 완료 |
| EC2 Spot Instance interruptions | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-interruptions.html | 완료 |
| AWS Batch with Spot | https://docs.aws.amazon.com/batch/latest/userguide/spot.html | 완료 |
| Serverless Lens 9 design principles | https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/design-principles.html | **보강 필요 (Stage 1)** |
| Lambda SnapStart | https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html | **보강 필요 (Stage 1)** |
| Aurora Serverless v2 | https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2.html | **보강 필요 (Stage 1)** |
| DynamoDB Capacity Modes | https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadWriteCapacityMode.html | **보강 필요 (Stage 1)** |
| S3 Express One Zone | https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-express-one-zone.html | **보강 필요 (Stage 1)** |
| Step Functions Express vs Standard | https://docs.aws.amazon.com/step-functions/latest/dg/concepts-standard-vs-express.html | **보강 필요 (Stage 1)** |

---

## 2. Lambda — 트레이드오프 사실

**출처**: Lambda quotas 페이지.

### 2.1 정량 한계

| 항목 | 값 | Increasable |
|------|-----|-------------|
| 동시 실행 쿼터 | 1,000 | 예 (수만까지) |
| 지속 실행(durable) | 1,000,000 | 예 (수백만까지) |
| 함수 메모리 | 128-10,240 MB (1MB 단위) | 아니오 |
| 함수 타임아웃 | 900초 | 아니오 |
| 환경변수 총합 | 4 KB | 아니오 |
| 리소스 기반 정책 | 20 KB | 아니오 |
| Layer | 함수당 5개 | 아니오 |
| 동시성 스케일링 한도 | 함수당 10초마다 1,000 실행환경 | 아니오 |
| 요청 페이로드 (동기) | 6 MB | 아니오 |
| 응답 페이로드 (동기) | 6 MB | 아니오 |
| 스트리밍 응답 | 200 MB | 아니오 |
| 요청·응답 (비동기) | 1 MB | 아니오 |
| 스트리밍 대역폭 | 처음 6MB 무제한, 이후 2MB/s | 아니오 |
| zip 배포 | 50 MB (업로드) / 250 MB (unzipped, layer 포함) | 아니오 |
| 컨테이너 이미지 | 10 GB (unzipped) | 아니오 |
| 컨테이너 이미지 설정 | 16 KB | 아니오 |
| `/tmp` | 512 MB-10,240 MB (1MB 단위) | 아니오 |
| 파일 디스크립터 | 1,024 (Managed Instances: 4,096) | 아니오 |
| 스레드/프로세스 | 1,024 (Managed Instances: Bottlerocket 기본) | 아니오 |
| 1 vCPU 등가 메모리 | 1,769 MB | - |

### 2.2 트레이드오프 함의

- **15분 초과 불가**: 긴 배치는 Step Functions 분해 또는 Batch/Fargate.
- **페이로드 6MB 한계**: 대용량 응답은 스트리밍(200MB) 또는 S3 presigned URL.
- **메모리=CPU 연동**: 1,769 MB에서 1 vCPU. 지연 최적화 시 메모리 상향 → CPU 상향 (비용도 비례).
- **동시성 1,000 기본**: API Gateway 기본 10,000 RPS와 불일치. 부하 테스트로 미리 확인.
- **쿼터 증액**: New 계정은 축소 쿼터, 사용 패턴 따라 자동 증액. 운영 전 명시적 요청 권장.

---

## 3. SageMaker Managed Spot Training — 트레이드오프 사실

**출처**: Managed Spot Training 페이지.

### 3.1 정량

- **절감**: on-demand 대비 최대 **90%**.
- **공식**: `(1 - BillableTimeInSeconds / TrainingTimeInSeconds) × 100`.
- **예**: Billable=100, Training=500 → 절감 80%.
- **조건**: `MaxWaitTimeInSeconds > MaxRuntimeInSeconds`.
- **체크포인트 미사용 시**: 내장·마켓플레이스 알고리즘 `MaxWaitTime ≤ 3600s`.

### 3.2 상태 전이

- 인터럽트 없음: `Starting → Downloading → Training → Uploading`
- 1회 인터럽트 후 재개: `Starting → Downloading → Training → Interrupted → Starting → Downloading → Training → Uploading`
- 2회 인터럽트 + MaxWait 초과: `Stopped: MaxWaitTimeExceeded`
- 스팟 미획득: `Starting → Stopping → Stopped: MaxWaitTimeExceeded`

### 3.3 체크포인트

SageMaker는 로컬 경로를 S3와 동기화. 재시작 시 S3에서 로컬로 복원. 짧은 잡이 아니면 체크포인트 **권장**.

### 3.4 자동 모델 튜닝 호환

Managed Spot은 Hyperparameter Tuning에서도 사용 가능.

---

## 4. Fargate Spot — 트레이드오프 사실

**출처**: ECS Fargate capacity providers 페이지.

### 4.1 핵심 동작

- **2분 경고**: 태스크 상태 변경 이벤트가 EventBridge로, SIGTERM이 컨테이너로.
- **`stopTimeout`**: 기본 30초, 최대 120초. SIGKILL 전 grace 기간.
- **용량 부족**: Fargate Spot 용량이 없으면 태스크 시작이 지연됨. **자동으로 On-Demand 전환하지 않음**.
- **서비스 + Spot**: 인터럽트 시 스케줄러가 추가 태스크 시작 시도.
- **단일 태스크**: 용량 복구까지 중단.

### 4.2 정전 이벤트 예시

```json
{
  "detail-type": "ECS Task State Change",
  "detail": {
    "stoppedReason": "Your Spot Task was interrupted.",
    "stopCode": "SpotInterruption",
    ...
  }
}
```

### 4.3 트레이드오프 함의

- Fargate Spot은 서비스 단위로 운영해야 안전. 배치 태스크는 Batch + Fargate Spot 조합.
- Capacity Provider Strategy로 `FARGATE` + `FARGATE_SPOT` weight 혼합 권장.
- SIGTERM 미처리 시 데이터 손상/손실 가능.

---

## 5. EC2 Spot — 트레이드오프 사실

**출처**: Spot Instance interruptions 페이지.

### 5.1 인터럽트 사유

- **Capacity**: EC2가 용량을 다시 필요로 할 때 (주 원인). 하드웨어 유지·폐기 포함.
- **Price**: 최대가 지정 시 Spot 가격이 초과하면. **최대가 지정은 인터럽트 빈도 증가**.
- **Constraints**: launch group/AZ group 등 제약 충족 불가 시.

### 5.2 인터럽트 동작

- `terminate` (기본): 인스턴스 종료.
- `stop`: persistent 요청일 때만. EBS 보존, 시작은 EC2만 가능.
- `hibernate`: 즉시 시작 (2분 경고 없음). 인스턴스 패밀리·AMI 지원 필요.

### 5.3 신호

- **2분 경고**: EventBridge 이벤트 + IMDSv2 메타데이터 (`/meta-data/spot/instance-action`).
- **Rebalance recommendation**: 인터럽트 리스크 상승 시 선제 신호. 2분보다 이른 활용 가능.
- **권장 폴링**: 5초 간격 메타데이터 확인.

### 5.4 운영 권장

- ASG(Auto Scaling Group) + 다중 인스턴스 타입 + 다중 AZ.
- 체크포인트 + S3/DynamoDB 영속화.
- AWS FIS로 사전 검증.
- `BidEvictedEvent` (CloudTrail)로 사후 추적.

---

## 6. AWS Batch with Spot — 트레이드오프 사실

**출처**: AWS Batch with Spot 페이지(AI 요약 포함).

### 6.1 할당 전략

| 전략 | 특성 | Spot 권장도 |
|------|------|-------------|
| `BEST_FIT` | 최소 가용 인스턴스 | 낮음 (인터럽트률 높음) |
| `BEST_FIT_PROGRESSIVE` | 필요 시 상위 인스턴스 승격 | 중간 |
| `SPOT_CAPACITY_OPTIMIZED` | 인터럽트 가능성 최소 | **표준** |

### 6.2 권장 구성

- `retryStrategy.attempts = 2~3`
- `evaluateOnExit`로 재시도 사유 구분
- SIGTERM 핸들러
- 체크포인트/복구
- Spot compute-env 우선 + On-Demand fallback 큐

### 6.3 워크로드 적합성

- **Spot 적합**: 배치, ML 훈련, CI/CD (fault-tolerant, retryable).
- **Spot 부적합**: 프로덕션 API, 데이터베이스, SLA 엄격 작업.

---

## 7. Serverless Lens — 1차 발췌

**출처**: Serverless Applications Lens welcome 페이지.

- 발행: **2022-07-14**.
- 스코프: 서버리스 워크로드 설계·배포·아키텍처.
- WA 기본 프레임워크와의 관계: 보완. 서버리스 특화 best practice만 수록.

### 7.1 보강 필요 (Stage 1에서 수집)

아래 URL에서 9개 design principles 발췌:
- https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/design-principles.html

5 pillars (Operational Excellence / Security / Reliability / Performance / Cost) 각각의 서버리스 특화 질문 및 best practice도 스냅샷 필요:
- https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/the-pillars-of-the-well-architected-framework.html

---

## 8. 추가 수집 우선순위 (Stage 1)

### 8.1 SnapStart
Lambda Java/Python 콜드 스타트 대안. 초기화 결과를 스냅샷에 저장, Restore 시 수 ms 내 재개.
- 제약: 버전된 함수만, 런타임 제한, 네트워크 초기화 주의.

### 8.2 Aurora Serverless v2
- ACU 단위 스케일링 (0.5 ~ 256 ACU 범위).
- Cold start 없음 (Serverless v1 대비).
- 최소 ACU > 0 시 바닥 비용 발생.
- Tier 3 RDS → Aurora 이행의 기본 경로.

### 8.3 DynamoDB
- On-Demand vs Provisioned 트레이드오프.
- 단일 테이블 디자인의 쿼리 유연성 감소.
- Strong vs Eventual consistency 선택.
- RCU/WCU 모델.

### 8.4 S3 Express One Zone
- 단일 AZ, 10x 저지연.
- 디렉토리 버킷 네이밍.
- 가격 모델 차이.
- 고처리량 배치 워크로드 용.

### 8.5 Step Functions
- Standard vs Express:
  - Standard: 최대 1년, 시각적 워크플로, 정확히 한 번 실행, 상대적 고비용.
  - Express: 최대 5분, 초당 10만 실행, at-least-once, 저비용.

### 8.6 EventBridge vs SQS vs Kinesis
- EventBridge: 이벤트 라우팅, 풍부한 필터링, 스키마 레지스트리.
- SQS: 작업 큐, FIFO 옵션, 긴 폴링.
- Kinesis: 스트리밍, 샤드 기반, 순서 보장.

---

## 9. 인용 포맷 규칙 (스킬 references/에서 사용)

모든 사실은 다음 형식으로 기록:

```markdown
> **사실**: Lambda 함수 타임아웃은 최대 900초(15분)다.
> **출처**: [AWS Docs — Lambda quotas §Function configuration](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html) (Snapshot 2026-04-18)
> **스킬에서의 함의**: 15분 초과 작업은 Step Functions 분해 또는 Batch·Fargate로 위임.
```

---

## 10. 검증 사례(Case Studies) 크로스 레퍼런스

### 10.1 serverless-autoresearch

- 경로: `/Users/dohyunjung/Workspace/roboco-io/research/serverless-autoresearch/`
- 주요 자료:
  - `docs/insights.md` — 15개 인사이트 (번호 고정).
  - `docs/comparison-report.md` — Sequential vs Parallel Spot.
  - `docs/spot-capacity-guide.md` — 지역 선택.
  - `experiments/003-h100-comparison/results-summary.md` — H100 검증.
- 본 RESEARCH에서 사용된 상수:
  - 48 실험 총비용: $3.94.
  - H100 단일 Spot run: 229초, $0.16.
  - upstream 대비: $7~24 / 8h.
  - Karpathy 재현: val_bpb 0.9951 vs 원본 ~0.998.

### 10.2 serverless-openclaw

- 경로: `https://github.com/serithemage/serverless-openclaw`
- 본 RESEARCH에서 사용된 상수:
  - 월 목표 비용: **under $1-2/month** (Free Tier 시 $0.23).
  - Lambda Container 콜드 스타트: **1.35s**.
  - ECS Fargate Spot 컴퓨트 절감: **70%**.
  - API Gateway 선택으로 ALB 고정비 **$18-25/월** 제거.
  - EventBridge scheduled pre-warming으로 **0s first response**.
  - Primary: Lambda Container, Fallback: ECS Fargate Spot.

---

## 11. Open issues

1. **Serverless Lens 9 설계원칙 텍스트 원문** 수집 (Stage 1 우선).
2. **Aurora Serverless v2 / DynamoDB / S3 Express / Step Functions / EventBridge** 공식문서 스냅샷 (Stage 1).
3. **Lambda SnapStart** 한계·지원 런타임 (Stage 1).
4. **AWS prescriptive guidance**의 Strangler Fig / CDC migration URL 수집 (Stage 4).

---

## 12. Serverless Lens — Design Principles

**출처**: https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/general-design-principles.html (Snapshot 2026-04-18)

> **수집 노트**: 원래 TASKS에서 "9 design principles"를 기대했으나, 2026-04-18 기준 AWS Serverless Lens 공식문서의 `general-design-principles.html` 페이지는 **7개 원칙**만 공식 수록함. `design-principles.html` 엔드포인트는 빈 페이지로 리다이렉트됨. 아래 표는 현행 공식 문서 기준 7개를 그대로 인용함.

### 12.1 Principles 표

| # | Title (원문) | Summary (원문 1문장) | 본 스킬에서의 활용 |
|---|-------------|---------------------|-------------------|
| 1 | Speedy, simple, singular | Functions are concise, short, single-purpose, and their environment may live up to their request lifecycle. | Phase 2 워크로드 특성 평가 기준 (함수 단위 분해 가능성) |
| 2 | Think concurrent requests, not total requests | Serverless applications take advantage of the concurrency model, and tradeoffs at the design level are evaluated based on concurrency. | Phase 3 RPS → Lambda 동시성 쿼터 매핑 |
| 3 | Share nothing | Function runtime environment and underlying infrastructure are short-lived, therefore local resources such as temporary storage is not guaranteed. | Phase 2 상태 저장성 평가 (S3/DynamoDB 위임 트리거) |
| 4 | Assume no hardware affinity | Underlying infrastructure may change. Use code or dependencies that are hardware-agnostic. | Phase 4 타겟 런타임 선정 (GPU/특수 CPU 의존 워크로드는 비적합) |
| 5 | Orchestrate your application with state machines, not functions | Chaining Lambda executions within the code to orchestrate the workflow of your application results in a monolithic and tightly coupled application. Instead, use a state machine to orchestrate transactions and communication flows. | Phase 4 Step Functions 도입 권고 근거 |
| 6 | Use events to trigger transactions | Events such as writing a new Amazon S3 object or an update to a database allow for transaction execution in response to business functionalities. | Phase 4 EventBridge/SQS 기반 이벤트 드리븐 전환 근거 |
| 7 | Design for failures and duplicates | Operations triggered from requests or events must be idempotent, as failures can occur and a given request or event can be delivered more than once. | Phase 4 멱등성 요구 (Spot 인터럽트 재시도와 결합) |

### 12.2 함의

- **원칙 1,2,3**: Tier 1 배치 / Tier 2 API 모두 Lambda 적합성 판단의 3대 필터.
- **원칙 4**: GPU/특수 라이브러리 의존 워크로드 → Fargate·EC2 Spot·SageMaker로 분기.
- **원칙 5,6**: Phase 4에서 Step Functions + EventBridge 조합을 "기본 권고"로 삼는 근거.
- **원칙 7**: Tier 1 Spot 재시도 전략과 자연스럽게 연결. 멱등성은 Spot 이식성의 선결 조건.

---

*본 리서치 작성: 2026-04-18. SPEC/PLAN과 쌍을 이루며 implementation Stage 1에서 보강.*
