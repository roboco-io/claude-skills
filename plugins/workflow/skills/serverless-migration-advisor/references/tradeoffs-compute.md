> **Snapshot date**: 2026-04-18
> **Description**: Lambda / Fargate / Batch / SageMaker / EC2 Spot 공식 트레이드오프

# Compute Service Tradeoffs

각 서비스의 AWS 공식 한계와 이행 관점의 함의. 모든 수치는 `[AWS Docs]` 또는 `[Insight #N]`로 traceable.
상세 Spot 공통 주제(인터럽트 신호·용량 선택·HUGI)는 [tradeoffs-spot.md](tradeoffs-spot.md)로 분리.

## 1. AWS Lambda

Primary citation: [AWS Docs — Lambda quotas](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html)

### 1.1 정량 한계 (운영 판단에 중요한 항목만)

| 항목 | 값 | Increasable | 출처 |
|------|-----|-------------|------|
| 함수 타임아웃 | 900초 (15분) | 아니오 | [AWS Docs] |
| 함수 메모리 | 128-10,240 MB (1MB 단위) | 아니오 | [AWS Docs] |
| 1 vCPU 등가 메모리 | 1,769 MB | - | [AWS Docs] |
| 동시 실행 쿼터 | 1,000 | 예 (수만까지) | [AWS Docs] |
| 지속 실행(durable) | 1,000,000 | 예 | [AWS Docs] |
| 동시성 스케일링 한도 | 10초마다 +1,000 실행환경 | 아니오 | [AWS Docs] |
| 요청·응답 페이로드 (동기) | 6 MB · 6 MB | 아니오 | [AWS Docs] |
| 스트리밍 응답 | 최대 200 MB | 아니오 | [AWS Docs] |
| 스트리밍 대역폭 | 처음 6MB 무제한, 이후 2 MB/s | 아니오 | [AWS Docs] |
| 비동기 요청·응답 | 1 MB | 아니오 | [AWS Docs] |
| zip 배포 | 50 MB (업로드) / 250 MB (unzipped, layer 포함) | 아니오 | [AWS Docs] |
| 컨테이너 이미지 | 10 GB (unzipped) | 아니오 | [AWS Docs] |
| `/tmp` | 512 MB-10,240 MB (1MB 단위) | 아니오 | [AWS Docs] |
| 환경변수 총합 | 4 KB | 아니오 | [AWS Docs] |
| Layer | 함수당 5개 | 아니오 | [AWS Docs] |

### 1.2 이행 관점 함의

- **15분 상한이 Tier 1 배치 분기의 기준선** — 15분을 넘기면 Step Functions 분해 또는 AWS Batch/Fargate로 위임. [AWS Docs]
- **메모리 = CPU 연동**: 1,769 MB에서 1 vCPU 등가. 지연 최적화 시 메모리 상향은 CPU 상향과 **비용을 동시에** 상향시킨다. [AWS Docs]
- **동시성 1,000 기본값 vs API Gateway 10,000 RPS 기본값 불일치** — 부하 테스트 전에 증액 요청 필수. [AWS Docs]
- **콜드 스타트 완화 수단은 서로 배타적**: Provisioned Concurrency 또는 SnapStart 중 택일 (SnapStart는 Java/Python 3.12+/.NET 8+ 지원, 컨테이너 이미지 불가). [AWS Docs — Lambda SnapStart] ([RESEARCH §13])
- **6MB 동기 페이로드**가 REST API의 실질 상한 — 대용량 응답은 스트리밍(200MB) 또는 S3 presigned URL로 우회. [AWS Docs]
- **컨테이너 이미지 10GB** 허용으로 대형 의존성(Java, ML) 배포는 가능하되 SnapStart 미지원이라 트레이드오프 존재. [AWS Docs]

### 1.3 When to choose / When to avoid

| 적합 | 부적합 |
|------|--------|
| 이벤트 기반 짧은 핸들러 (≤15분) | 장시간 배치·훈련 |
| Spiky 트래픽 (Zero-idle 목표) [Case: openclaw] | 지속 연결 (WebSocket long-lived), gRPC streaming |
| 동시 요청 < 1,000 · 증액 가능 | 6MB 초과 동기 응답 |
| Node/Python/Java/.NET 함수형 워크로드 | GPU·특수 CPU 의존 (→ SageMaker/EC2) |

## 2. SageMaker Managed Spot Training

Primary citation: [AWS Docs — SageMaker Managed Spot Training](https://docs.aws.amazon.com/sagemaker/latest/dg/model-managed-spot-training.html)

### 2.1 정량

| 항목 | 값 | 출처 |
|------|-----|------|
| 절감 한도 | on-demand 대비 **최대 90%** | [AWS Docs] |
| 절감률 공식 | `(1 - BillableTimeInSeconds / TrainingTimeInSeconds) × 100` | [AWS Docs] |
| 예시 | Billable=100s, Training=500s → 절감 80% | [AWS Docs] |
| 필수 조건 | `MaxWaitTimeInSeconds > MaxRuntimeInSeconds` | [AWS Docs] |
| 체크포인트 미사용 (내장·마켓플레이스 알고리즘) | `MaxWaitTime ≤ 3600s` | [AWS Docs] |
| Hyperparameter Tuning 호환 | 지원 | [AWS Docs] |

### 2.2 상태 전이 예

- 인터럽트 없음: `Starting → Downloading → Training → Uploading` [AWS Docs]
- 1회 인터럽트 후 재개: `Starting → Downloading → Training → Interrupted → Starting → Downloading → Training → Uploading` [AWS Docs]
- MaxWait 초과 종료: `Stopped: MaxWaitTimeExceeded` [AWS Docs]
- Spot 미획득: `Starting → Stopping → Stopped: MaxWaitTimeExceeded` [AWS Docs]

### 2.3 이행 관점 함의

- **Billable은 Training 시간만 포함** — Starting/Downloading 구간은 과금되지 않음. HUGI 원칙의 AWS 공식 구현. [AWS Docs]
- **체크포인트는 S3↔로컬 자동 동기화**이므로 짧은 잡이 아니면 반드시 활성화. [AWS Docs]
- **시작 오버헤드 ~3분**은 실제 절감률을 훼손 — 5분 훈련 잡의 60%가 오버헤드. 실험을 합치거나 warm pool 사용. [Insight #5]
- **검증 사례**: 48 실험 $3.94, H100 229s $0.16 vs upstream H100 8h $7~24. [Case: autoresearch] [Insight #15]
- **쿼터는 First-class concern** — GPU Spot 기본 0, p5/p6은 수동 검토. 리전별·인스턴스별 사전 요청. [Insight #6]

## 3. AWS Fargate + Fargate Spot

Primary citation: [AWS Docs — Fargate capacity providers](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-capacity-providers.html)

### 3.1 핵심 동작

| 항목 | 값 | 출처 |
|------|-----|------|
| 인터럽트 경고 | 2분 (EventBridge + SIGTERM) | [AWS Docs] |
| `stopTimeout` | 기본 30초, 최대 120초 | [AWS Docs] |
| 용량 부족 시 시작 | 지연만 발생, **자동 On-Demand 전환 없음** | [AWS Docs] · [Insight #O1] |
| 서비스 단위 운영 | 인터럽트 시 스케줄러가 추가 태스크 시작 시도 | [AWS Docs] |
| 단일 태스크 운영 | 용량 확보까지 **중단** — 가용성 위험 | [AWS Docs] |

### 3.2 이행 관점 함의

- **자동 fallback 없음**을 용량공급자 혼합(`FARGATE` + `FARGATE_SPOT` weight)으로 설계 시점에 해결해야 함. [Insight #O1] openclaw는 Lambda Container를 기본으로 두고 Fargate Spot을 fallback으로 배치하여 이 문제를 우회. [Case: openclaw]
- **서비스 + `desiredCount ≥ 2`가 단일 배포의 최소 조건** — 단일 태스크 + Fargate Spot은 가용성 측면에서 안티패턴. [AWS Docs]
- **SIGTERM 핸들러 의무** — 2분 내 드레인·상태 저장 실패 시 데이터 손상 위험. [AWS Docs]
- **정전 이벤트 JSON**은 `stopCode: "SpotInterruption"`으로 관측 — CloudWatch 알람·자동 교체 로직에 활용. [AWS Docs]

## 4. Amazon EC2 Spot

Primary citation: [AWS Docs — EC2 Spot Instance interruptions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-interruptions.html)

### 4.1 인터럽트 사유 3종

| 사유 | 설명 | 출처 |
|------|------|------|
| Capacity | EC2가 용량을 다시 필요로 할 때 — **주 원인** | [AWS Docs] |
| Price | 최대가 지정 시 Spot 가격이 초과하면 | [AWS Docs] |
| Constraint | launch group / AZ group 제약 충족 불가 시 | [AWS Docs] |

### 4.2 인터럽트 동작 비교

| 동작 | 특성 | 조건 |
|------|------|------|
| `terminate` (기본) | 인스턴스 종료 | 항상 가능 |
| `stop` | EBS 보존, 재시작은 EC2만 가능 | **persistent 요청 전용** |
| `hibernate` | 메모리 상태 보존, 복원 즉시 시작 (2분 경고 없음) | 인스턴스 패밀리·AMI 지원 필요 |

### 4.3 이행 관점 함의

- **최대가 지정은 안티패턴** — 인터럽트 빈도가 증가하기 때문에 기본값(On-Demand 가격 상한) 유지가 최선. [AWS Docs]
- **Rebalance recommendation 신호**는 2분 경고보다 먼저 발생 — ASG와 결합하면 사실상 더 긴 drain 여유 확보. [AWS Docs]
- **CloudTrail `BidEvictedEvent`** + EventBridge로 사후 추적. [AWS Docs]
- **AWS FIS로 사전 검증**: 인터럽트 주입 테스트를 운영 전 파이프라인에 포함. [AWS Docs — FIS]
- **다중 AZ + 다중 인스턴스 타입 + ASG**의 3종 세트가 운영 최소 요건. [AWS Docs] · [Insight #1]
- **long-running GPU 작업**은 `hibernate`로 체크포인트 비용 절감 — 단 인스턴스 패밀리 제약 확인 필수. [AWS Docs]

## 5. AWS Batch (with Spot)

Primary citation: [AWS Docs — AWS Batch with Spot](https://docs.aws.amazon.com/batch/latest/userguide/spot.html)

### 5.1 3가지 할당 전략 비교

| 전략 | 특성 | Spot 권장도 | 출처 |
|------|------|-------------|------|
| `BEST_FIT` | 최소 가용 인스턴스만 선택 | 낮음 (인터럽트률 높음) | [AWS Docs] |
| `BEST_FIT_PROGRESSIVE` | 용량 부족 시 상위 인스턴스로 승격 | 중간 | [AWS Docs] |
| `SPOT_CAPACITY_OPTIMIZED` | 인터럽트 가능성 최소화 | **Spot 표준** | [AWS Docs] |

### 5.2 이행 관점 함의

- **`SPOT_CAPACITY_OPTIMIZED` = Spot 기본값** — 다른 전략은 비용보다 가용성이 열악할 수 있음. [AWS Docs]
- **`retryStrategy.attempts ≥ 2` + `evaluateOnExit`** 조합으로 인터럽트 재시도와 실제 오류를 구분. [AWS Docs]
- **큐 우선순위 패턴**: Spot compute-env 우선 + On-Demand fallback 큐 — 배치 워크로드에서의 표준 안전망. [AWS Docs]
- **SIGTERM 핸들러 + 체크포인트**가 컨테이너 이미지 수준에서 준비돼야 함. [AWS Docs]
- **적합 워크로드**: 배치, ML 훈련, CI/CD 등 fault-tolerant · retryable. **부적합**: 프로덕션 API · DB · 엄격 SLA 작업. [AWS Docs]

## 6. When to choose what (decision matrix)

| 워크로드 패턴 | 추천 서비스 | 근거 |
|---------------|-------------|------|
| ≤15분 단일 처리 · 이벤트 트리거 | Lambda | 15분 상한 [AWS Docs §1.1] |
| 15분~수시간 배치 · retryable | AWS Batch (Spot, `SPOT_CAPACITY_OPTIMIZED`) | [AWS Docs §5] |
| ML 훈련 (체크포인트 가능) | SageMaker Managed Spot Training | 최대 90% 절감 [AWS Docs] + 229s $0.16 검증 [Case: autoresearch] |
| 상시 컨테이너 워크로드 (서비스형) | Fargate + Fargate Spot 혼합 (`capacityProviderStrategy`) | fallback 없음 보완 [Insight #O1] |
| 상시 API (spiky · zero-idle 우선) | Lambda + API Gateway (primary) + Fargate Spot fallback | [Case: openclaw] [Insight #O2] |
| 장기 GPU 작업 · 인터럽트 허용 | EC2 Spot (hibernate 또는 체크포인트) | [AWS Docs §4] |
| 워크플로 오케스트레이션 (≤5분) | Step Functions Express | [AWS Docs — Step Functions §17] |
| 워크플로 오케스트레이션 (≤1년) | Step Functions Standard | [AWS Docs — Step Functions §17] |
