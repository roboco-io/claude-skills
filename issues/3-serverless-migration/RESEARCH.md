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

### 10.1.1 Numbered Insights (stable references)

스킬 `references/case-study-autoresearch.md`에서 인용할 고정 번호 테이블. 제목은 `docs/insights.md` 원문 헤더를 그대로 옮김.

| # | Title | One-line lesson | Tier usage |
|---|-------|-----------------|------------|
| 1 | Spot Capacity Varies Dramatically by Region | 동일 인스턴스 타입도 리전마다 placement score 1~9 편차 → `aws ec2 get-spot-placement-scores` 필수 | Tier 1 배치 |
| 2 | Larger Instances Can Be Cheaper on Spot | g7e.8xlarge가 g7e.2xlarge보다 싼 경우 존재 — 사이즈=비용 가정 금지, Spot price history 직접 확인 | Tier 1 배치 |
| 3 | DEVICE_BATCH_SIZE ≠ Token Throughput (hardware-dependent — see also #13) | TOTAL_BATCH_SIZE 고정 시 DEVICE_BATCH_SIZE만 올려도 토큰 처리량은 불변, 오히려 val_bpb 악화 (L40S/SDPA) | Tier 1 배치 |
| 4 | Flash Attention 3 is GPU-Architecture Specific | FA3 커널은 Hopper/Ampere만 지원, Ada Lovelace(L40S)는 런타임 CUDA 오류 → 아키텍처별 fallback 필수 | Tier 1 배치 |
| 5 | SageMaker Startup Overhead is Significant | 잡당 ~3분 시작 오버헤드 → 5분 훈련 잡의 60%가 오버헤드. 단일 잡에 실험 병합 또는 warm pool | Tier 1 배치 |
| 6 | Quota Management is a First-Class Concern | GPU Spot 쿼터 기본값 0, g7e 자동승인 / p5·p6는 수동 검토. 마이그레이션 전 다중 리전 쿼터 사전 요청 | Tier 1 배치 |
| 7 | SageMaker Profiler Doesn't Support All Instance Types | g7e는 `ValidationException: Profiler is currently not supported` → Estimator에 `disable_profiler=True` | Tier 1 배치 |
| 8 | The Parallel Evolution Approach Works | 4 병렬 실험 $0.066, ~10분 wall clock — autonomous 파이프라인 검증됨 | Tier 1 배치 |
| 9 | PyArrow Version Matters | DLC의 pyarrow 23.x와 로컬 이전 버전 불일치 시 parquet `Repetition level histogram size mismatch`. `pyarrow>=21.0.0` 필수 | Tier 1 배치 |
| 10 | config.yaml Should Never Be in Git | 역할 ARN·프로필·리전 등 환경별·민감 정보 포함 → gitignore + `.example` 템플릿 | Tier 1 배치 (운영 원칙) |
| 11 | Spot GPUs Are Valid Proxies for Large-Scale Training | L40S Spot HPO 결과가 H100 프로덕션에 전이 (랭킹·아키텍처 결정). 절대 BPB·최적 BS는 미전이 | Tier 1 배치 |
| 12 | DEVICE_BATCH_SIZE ≠ More Training (L40S-specific; reversed on H100) | BS 64→128이 L40S에서는 악화, H100/FA3에서는 개선 — 하드웨어별 상반된 방향 | Tier 1 배치 |
| 13 | Batch Size × LR × Hardware Interact — Evolved LRs Can Be BS-Specific | BS 고정한 LR 진화는 BS-조건부 최적일 뿐. 하드웨어·BS 변경 시 LR 재방문 필요. 단일 가정 점검이 20실험 탐색보다 **100× 비용효율** | Tier 1 배치 |
| 14 | Cheap-GPU-Evolved LRs Transfer to Expensive GPUs — Sometimes Better Than Re-Evolving | L40S($0.40 24실험)에서 찾은 LR을 H100에 옮겨 upstream baseline 이하 달성. Phase-2 H100 재탐색이 오히려 악화 | Tier 1 배치 |
| 15 | Serverless Spot Can Match or Beat Dedicated H100 Results at 44–150× Lower Cost | 229초 single Spot run ($0.16)으로 Karpathy upstream H100 8h ($7-24) val_bpb 일치 혹은 상회 | Tier 1 배치 (핵심 서사) |

**Source commit (autoresearch)**: `5435b374fb5daae5eee95e3e8eb9292caacf94f8`
**Source path**: `docs/insights.md`
**Extraction date**: 2026-04-18

### 10.2 serverless-openclaw

- 경로: `https://github.com/serithemage/serverless-openclaw`
- 본 RESEARCH에서 사용된 상수:
  - 월 목표 비용: **under $1-2/month** (Free Tier 시 $0.23).
  - Lambda Container 콜드 스타트: **1.35s** (warm 0.12s).
  - ECS Fargate Spot 컴퓨트 절감: **70%**.
  - API Gateway 선택으로 ALB 고정비 **$18-25/월** 제거.
  - EventBridge scheduled pre-warming으로 **0s first response**.
  - Primary: Lambda Container, Fallback: ECS Fargate Spot.

### 10.2.1 Numbered Principles (stable references)

스킬 `references/case-study-openclaw.md`에서 인용할 고정 번호 테이블. autoresearch의 numeric insight (§10.1.1)와 구분하기 위해 **O1-O5** prefix 사용.

| # | Principle from openclaw | One-line lesson | Tier usage |
|---|------------------------|-----------------|------------|
| O1 | Lambda Container + dual compute fallback | 기본 Lambda Container(zero-idle, 1.35s cold start), 15분 초과·고부하는 ECS Fargate Spot fallback(~70% 컴퓨트 절감) | Tier 2 API |
| O2 | API Gateway over ALB | ALB 고정비 **$18-25/월** 제거 → per-request 청구 모델로 전환 | Tier 2 API |
| O3 | EventBridge scheduled pre-warming | 액티브 시간대 cron으로 컨테이너 주기 호출, 월 ~$0.07 추가로 first-response 콜드스타트 페널티 제거 | Tier 2 API |
| O4 | DynamoDB + S3 session persistence for stateless Lambda | DynamoDB에 대화/설정, S3에 세션 백업(동시성 제어) → Stateless Lambda에서 대화 지속성 확보 | Tier 2 API |
| O5 | Free-tier first cost target | 개인 사용 **$1-2/월** (Free Tier 내 $0.23) 목표 — 전 구성요소의 zero-idle·per-request 원칙 적용 결과 | Tier 2 API |

**Source**: https://github.com/serithemage/serverless-openclaw (README, 2026-04-18 snapshot)

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

## 13. Lambda SnapStart — 트레이드오프 사실

**출처**: https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html (Snapshot 2026-04-18)

### 13.1 정량

| 항목 | 값 |
|------|-----|
| 지원 런타임 | **Java 11+, Python 3.12+, .NET 8+** (Node.js, Ruby, OS-only, 컨테이너 이미지 미지원) |
| 복원 지연 | "as low as sub-second" — 저지연 최적 시나리오에서 1초 미만 |
| 적용 단위 | **게시된 버전(published version) 또는 버전을 가리키는 alias** (unqualified `$LATEST` 불가) |
| 추가 비용 | **Java: 무료** (요청·실행시간·메모리만 청구). **Python/.NET: 캐시 + 복원 비용** 추가 (메모리 기반, 리전 단가) |
| 최소 캐시 청구 | Python/.NET: **최소 3시간분** (함수가 active 상태 유지 시 지속 과금) |
| 스냅샷 보존 (Java) | **14일 미호출 시 Inactive** → 다음 호출 시 재초기화 필요 (`SnapStartNotReadyException`) |
| 미지원 조합 | Provisioned Concurrency, Amazon EFS, 512MB 초과 ephemeral storage |
| 지원 리전 | 모든 상용 리전 (ap-southeast-NZ, ap-east-Taipei 제외) |

### 13.2 제외 / 주의 사항

- **VPC ENI 수명주기**: 스냅샷에 포함되지 않음. 복원 시 ENI 재연결 지연 가능.
- **고유성(Uniqueness) 함정**: 스냅샷 시점의 난수·UUID·TLS 세션 키·시드 값이 모든 복원 인스턴스에 복제됨 → 보안 크리티컬. 초기화 단계가 아닌 **핸들러 내부에서 생성** 권장.
- **런타임 훅**: `beforeCheckpoint` / `afterRestore` 훅으로 uniqueness 및 커넥션 재확립 처리 (Java CRaC API, Python/.NET 전용 훅).
- **네트워크 커넥션**: DB/Redis/HTTP 커넥션 상태는 복원 후 **보장되지 않음**. AWS SDK 커넥션은 자동 재개.
- **임시 데이터**: 캐시된 타임스탬프/임시 자격증명은 핸들러에서 새로 갱신.
- **SDK 자격증명**: SnapStart 활성 시 Lambda는 access-key 환경변수 대신 `AWS_CONTAINER_CREDENTIALS_FULL_URI` 사용 (복원 전 만료 방지).
- **Provisioned Concurrency 상호배타**: 엄격한 콜드스타트 SLA가 필요하면 PC, 그 외는 SnapStart.

### 13.3 함의

- **Tier 2 API (Java/Python/.NET)**: 콜드 스타트가 SLA에 영향을 주는 사용자 대면 API에 1순위 권고.
- **네트워크 의존 초기화**: VPC 안에서 RDS/Redis 커넥션을 초기화하는 함수는 SnapStart 효과가 제한적 — ENI 연결이 병목.
- **uniqueness 함정**: 금융/인증 계열에서는 스냅샷 복원 후 반드시 fresh entropy 재생성 훅 의무화.
- **Java 이점**: 별도 비용 없이 활성화 가능 → Spring Boot Lambda 이식의 표준 권고.

---

## 14. Aurora Serverless v2 — 트레이드오프 사실

**출처**: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2.html (Snapshot 2026-04-18)

### 14.1 정량

| 항목 | 값 |
|------|-----|
| ACU 범위 | 엔진/플랫폼 버전별 `0.5-128` → `0.5-256` → **`0-256`** (최신 Aurora MySQL 3.08.0+ / PostgreSQL 13.15+, 14.12+, 15.7+, 16.3+) |
| ACU 정의 | 1 ACU ≈ **2 GiB RAM + 상응 CPU·네트워킹** |
| ACU 증분 | **0.5 ACU** 단위, 초 단위 연속 측정 |
| 스케일 반응성 | 수 초 이내, 온라인 스케일 (downtime 없음) |
| Auto-pause | min=0 설정 시 idle 후 자동 pause → 새 커넥션 도착 시 즉시 resume (스토리지 비용은 계속) |
| 콜드 스타트 | v1 대비 **제거** — 지속 실행 인스턴스. 단 auto-pause → resume 시 수 초 재개 지연 가능 |
| 최소 용량 청구 | 각 writer/reader 인스턴스별 `min ACU × 가동시간` (클러스터 2개 × min=1 → 최소 2 ACU 항상 과금) |
| Provisioned 호환 | 동일 클러스터 내 Provisioned + Serverless v2 **혼합** 가능 (리더·라이터 모두). 인스턴스 클래스 변경으로 상호 전환 |
| Multi-AZ | 지원 (Provisioned 클러스터와 동일한 failover 매커니즘) |
| Global Database | 지원 (v2 전용 리전 복제) |
| RDS Proxy | 지원 (Lambda ↔ Aurora 연결 풀링 최적 조합) |
| 미지원 | Database Activity Streams, Cluster Cache Management (Aurora PG), Aurora Auto Scaling (reader 인스턴스로 대체) |
| Promotion Tier | 0-1: writer와 동일 용량 자동 추적 / 2-15: 독립 스케일 |

### 14.2 v1 대비 차이

- v1: 콜드 스타트 존재, 자동 pause/resume, ACU 2배수 스텝, 수 분 단위 스케일.
- v2: 인스턴스 지속, 0.5 ACU 단위, 초 단위 스케일, Global Database 호환.

### 14.3 함의

- **Tier 3 RDS → Aurora 이행의 기본 경로**: DB 엔진 변경 없이 서버리스 과금 모델 도입.
- **바닥 비용 함정**: min ACU > 0 이면 idle 시에도 과금. 완전 zero-idle 원할 경우 min=0 + auto-pause 활용 (단, resume 지연 감수).
- **burst 트래픽 대응**: 0.5 ACU 단위 스케일로 Lambda 동시성 급증에 연동 가능.
- **혼합 운영**: 레거시 Provisioned 리더 유지 + Serverless v2 라이터 도입 점진 전환 가능.

---

## 15. DynamoDB Capacity Modes — 트레이드오프 사실

**출처**: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadWriteCapacityMode.html (Snapshot 2026-04-18)

### 15.1 On-Demand vs Provisioned

| 항목 | On-Demand | Provisioned |
|------|-----------|-------------|
| 청구 단위 | 요청당 (Read Request Unit / Write Request Unit) | 시간당 용량 예약 (RCU/WCU × hour) |
| RRU/WRU 정의 | 1 RRU = 최대 4KB strongly consistent read 1회 또는 eventually consistent read 2회 · 1 WRU = 최대 1KB write 1회 |
| 스케일링 | 자동, 신규 테이블도 즉시 4,000 writes/sec + 12,000 reads/sec 지원 | Auto Scaling으로 min/max 범위 내 자동 조정 (반응 수 분) |
| 피크 대응 | 이전 피크의 **2배**까지 즉시 허용. 30분 이내 2배 초과 시 throttle 가능 (pre-warming으로 사전 증가 가능) | max 이상 throttled, burst capacity (5분) 완충 |
| 바닥 비용 | 0 (호출 없으면 $0) | min RCU/WCU × 가동시간 |
| Reserved Capacity | 불가 | 1년 **최대 54%** / 3년 **최대 77%** 할인 (100 RCU/WCU 단위) |
| 모드 전환 | Provisioned → On-Demand: 24시간당 최대 4회 / On-Demand → Provisioned: 언제든 |
| 기본 쿼터 | 계정당 합산 **40,000 RCU/WCU**, On-Demand 테이블당 max 40,000 RCU + 40,000 WCU |
| 선택적 max 설정 | On-Demand에 **per-table max** 설정 가능 (비용 폭주 방지) |
| 적합 워크로드 | 예측 불가·스파이키·서버리스·신규 앱 (**기본 권고**) | 안정·예측 가능·지속 고부하 (Reserved 활용 시 비용 절감) |

### 15.2 함의

- **Tier 2 API 기본 권고**: On-Demand — Lambda 동시성 확장과 자연 매칭, idle 시 $0.
- **예측 가능 고부하**: Provisioned + Reserved Capacity로 On-Demand 대비 50~70% 절감 가능.
- **하이브리드**: GSI를 다른 capacity mode로 설정 가능 → 조회 빈도 차이 반영.
- **전환 정책**: 24시간 전환 제한은 마이그레이션 테스트 기간 동안 고려해야 함.

---

## 16. S3 Express One Zone — 트레이드오프 사실

**출처**: https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-express-one-zone.html (Snapshot 2026-04-18)
**보조 출처**: https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-overview.html

### 16.1 특성

| 항목 | 값 |
|------|-----|
| AZ 스코프 | **단일 AZ** (가용성 SLA 99.95%). 다중 디바이스 중복 저장이지만 AZ 간 복제 없음 |
| 지연 시간 | 한 자리 ms (S3 Standard 대비 ~10x 빠름) |
| 처리량 | 버킷당 **읽기 200,000 TPS / 쓰기 100,000 TPS** (쿼터 증가 가능) |
| 버킷 타입 | **Directory bucket** (S3 general purpose bucket과 별도 스키마) |
| 버킷 네이밍 | `{base-name}--{zone-id}--x-s3` (예: `my-bucket--usw2-az1--x-s3`), 3-63자 |
| 스토리지 구조 | **계층형 디렉토리** (slash delimiter로 폴더 자동 생성), GPB의 flat prefix와 다름 |
| 요청 가격 | Standard 대비 **약 50% 저렴** (per-request) |
| 스토리지 가격 | Standard 대비 단가 유사 혹은 소폭 저렴 (단위 per-GB 비용은 리전별 차이). **비용 이점의 주 원천은 요청 단가** |
| 일관성 | Strong read-after-write (기본) |
| 암호화 | SSE-S3(자동) 또는 SSE-KMS. **SSE-C 미지원** |
| ACL | 항상 bucket-owner-enforced (ACL 비활성) |
| Block Public Access | **항상 On** (해제 불가) |
| 데이터 전송 | 동일 AZ 내 EC2/ECS/Lambda에서 호출 시 DTO 비용 없음 |
| 쿼터 | 계정당 리전별 디렉토리 버킷 **100개** (증가 가능) |
| 기능 제한 | 버저닝 없음, Lifecycle 일부, CRR/SRR 없음, Intelligent-Tiering·Glacier 불가 |

### 16.2 권장 워크로드

- **적합**: 비디오 편집/크리에이티브, ML 훈련 데이터 random access, 실시간 분석, 인터랙티브 앱, shuffle/spill, 분석 중간 결과.
- **부적합**: 장기 아카이브, 다중 리전 재해복구, 규제 요구 다내구성 저장, 외부 공개 CDN 오리진, ACL 필요 워크로드.

### 16.3 함의

- **Tier 1 배치 워크로드 shuffle storage**: autoresearch nanoGPT 훈련 데이터 로딩 가속 후보. 단, EC2/Fargate Spot과 **동일 AZ** 배치 필수.
- **단일 AZ 제약**: AZ 장애 시 데이터 유실 가능 → 원본은 Standard/Glacier에 별도 보관, 중간 결과만 Express.
- **비용 역전 함정**: 저빈도 접근 시 Standard 대비 **총비용 증가** (요청 단가 절감은 요청 빈도에 비례).
- **네이밍 규칙**: `--{zone-id}--x-s3` 패턴 필수. IaC 템플릿/버킷명 생성 로직에 강제.
- **CreateSession auth 모델**: 객체 오퍼레이션 전 `s3express:CreateSession` 필요 → SDK 버전·IAM 정책 업그레이드 필요.

---

## 17. Step Functions — Standard vs Express

**출처**: https://docs.aws.amazon.com/step-functions/latest/dg/concepts-standard-vs-express.html (Snapshot 2026-04-18)

### 17.1 비교

| 항목 | Standard | Async Express | Sync Express |
|------|----------|---------------|--------------|
| 최대 실행 시간 | **1년** | 5분 | 5분 (콘솔 `StartSyncExecution`은 60s 만료, SDK/CLI는 5분까지) |
| 실행 시맨틱 | **Exactly-once** (내부 상태 영속) | **At-least-once** (상태 비영속, 중복 가능) | **At-most-once** (상태 비영속, 재시도 없음) |
| 실행 이력 | API로 조회, 콘솔 시각적 디버깅, **90일 보관** (30일로 단축 가능) | Step Functions 미포착 → CloudWatch Logs 활성화 필수 | CloudWatch Logs 활성화 필수 |
| 처리량 | state transition rate 제한 (account quota) | 초당 수만~수십만 실행 | account 용량 제한과 **분리** (자동 스케일) |
| 청구 모델 | **per state transition** | per execution × duration × memory | per execution × duration × memory |
| 지원 통합 | 모든 서비스 통합 + `.sync`, `.waitForTaskToken` | `.sync`, `.waitForTaskToken` 미지원 | `.sync`, `.waitForTaskToken` 미지원 |
| Distributed Map / Activities | 지원 | 미지원 | 미지원 |
| Idempotency | 동일 이름 재실행 시 자동 idempotent 응답 | 자동 관리 **없음** — 동명 동시 실행 가능 | 자동 관리 없음, 예외 시 재실행 없음 |

### 17.2 함의

- **Tier 1 배치 분해**: 15분 초과 배치는 Standard 워크플로로 분해. Spot 재시도 로직을 상태기계에 명시하고 exactly-once 보장 활용.
- **Tier 2 API 이벤트 후처리**: Async Express — 짧은 fan-out·스트리밍 이벤트, API 응답 후처리.
- **Tier 2 API 동기 마이크로서비스**: Sync Express — API Gateway 뒤 실시간 워크플로, at-most-once 수용 가능할 때.
- **at-least-once 함정**: Async Express는 중복 실행 가능 → 멱등성 설계(§12 원칙 7) 전제 필수. 비멱등 작업(예: 결제)은 Standard 선택.
- **5분 한계**: Express로는 장시간 워크플로 불가. Standard로 분할하거나 `StartExecution`으로 체인.
- **실행 이력**: 감사·디버깅 필요 시 Standard (90일 retention, 30일로 축소 요청 가능). 비용 우선이면 Express + 명시적 CloudWatch Logs.
- **Workflow type immutable**: state machine 생성 후 Standard↔Express 변경 불가 → 설계 초기 결정.

---

*본 리서치 작성: 2026-04-18. SPEC/PLAN과 쌍을 이루며 implementation Stage 1에서 보강.*
