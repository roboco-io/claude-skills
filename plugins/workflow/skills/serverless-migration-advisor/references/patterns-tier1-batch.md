> **Snapshot date**: 2026-04-18
> **Tier**: 1 (배치·훈련·ETL) — serverless-autoresearch로 검증
> **Description**: 배치·훈련·ETL 이행 패턴

# Tier 1 Migration Patterns — Batch / Training / ETL

이 문서의 모든 패턴은 [Case: autoresearch] 검증 사례 기반. 세부 수치는 RESEARCH.md §10.1.1 참조.

## 1. When Tier 1?

- 작업이 ephemeral — 매 실행마다 시작·종료하는 배치성 워크로드
- 인터럽트 허용 또는 체크포인트로부터 재개 가능 — Spot 기반 절감의 전제
- 비용 vs. wall-clock 절충 수용 — Spot 대기로 실행 시간이 다소 늘어도 과금 절감 이득이 큼
- 실행 당 독립 상태 — 이전 실행의 in-memory 상태에 의존하지 않음 (Serverless Lens 원칙 3 "Share nothing")

## 2. Patterns

### Pattern 1.1: EC2 long-running → SageMaker Managed Spot Training

**적용 조건** (when to use):
- ML 훈련·재훈련·HPO 워크로드
- 체크포인트 가능 (PyTorch/TF 표준 checkpoint API)
- 인터럽트 허용 (job-level retry 수용)
- GPU 사용 시간이 24시간 중 일부 (상시 GPU 불필요)

**AS-IS:**
```text
[User]
  |
  v
[EC2 H100 상시]───(cron or manual)───▶ [Training script]
   └─ idle 16h/day                          │
                                            v
                                       [S3 artifacts]

월 $3,000+ (H100 24h × $3/hr × 30d)
```

**TO-BE:**
```text
[User / Scheduler]
  |
  v
[SageMaker Training Job (Managed Spot, MaxWait>MaxRuntime)]
    Starting → Downloading → Training → (Interrupted → Starting) → Uploading
                                  │
                                  v
                             [S3 checkpoints + artifacts]

과금 = BillableTime (Training 구간만)
```

**핵심 변경:**
- 상시 GPU 인스턴스를 제거하고 훈련 잡 단위로 전환
- 체크포인트를 S3에 자동 동기화 (SageMaker 내장 기능) [AWS Docs — SageMaker]
- 리전 선택을 Spot placement score 기반으로 고정 [Insight #1]
- `MaxWaitTimeInSeconds > MaxRuntimeInSeconds` 조건 강제 [AWS Docs]

**트레이드오프:**
- **장점**: 과금 구간이 Training 시간만으로 축소 (HUGI 원칙), on-demand 대비 최대 90% 절감 [AWS Docs]
- **단점 1**: 잡당 ~3분 시작 오버헤드 — 5분 훈련 잡은 60%가 오버헤드 [Insight #5]. 실험 병합 또는 warm pool로 완화.
- **단점 2**: GPU Spot 쿼터 기본 0 — 리전·인스턴스별 사전 요청 필수 [Insight #6]
- **단점 3**: 하드웨어별 배치 사이즈·LR 재튜닝 필요 — L40S의 최적은 H100과 다를 수 있음 [Insight #13]

**비용 범위** (예시, 검증 사례 출처 필수):
- 48 실험 $3.94 (autoresearch autonomous HPO 전체 비용) [Case: autoresearch]
- H100 단일 Spot run 229초, $0.16 (Karpathy 원본 H100 8h $7-24 대비 44-150× 저렴) [Case: autoresearch] [Insight #15]
- 4-병렬 실험 $0.066, 약 10분 wall clock [Insight #8]

**이행 체크리스트 스켈레톤:**
- [ ] **Stage 0 (사전 준비)**:
  - [ ] `aws ec2 get-spot-placement-scores`로 리전별 Spot 용량 조사 [Insight #1]
  - [ ] GPU Spot 쿼터 증액 요청 (다중 리전) [Insight #6]
  - [ ] `disable_profiler=True` 적용 확인 (g7e 필요 시) [Insight #7]
  - [ ] 체크포인트 S3 경로·IAM 역할 준비
- [ ] **Stage 1 (저위험 검증)**:
  - [ ] 소규모 데이터로 dry-run (1 epoch) — Spot 할당·체크포인트 복원 확인
  - [ ] `MaxWaitTime` / `MaxRuntime` 설정 검증 — `MaxWaitTime > MaxRuntime` 강제
  - [ ] `(1 - BillableTime/TrainingTime) × 100` 절감률 측정
- [ ] **Stage 2 (파일럿)**:
  - [ ] 기존 EC2 잡과 동일 하이퍼파라미터로 1회 비교 실행
  - [ ] 인터럽트 주입 시나리오로 체크포인트 복구 확인 (AWS FIS 가능)
  - [ ] 하드웨어별 배치 사이즈 재검증 [Insight #13]
- [ ] **Stage 3 (전환)**:
  - [ ] EC2 상시 인스턴스 중단 (우선 stop, 일정 관측 후 terminate)
  - [ ] EventBridge Scheduler로 주기 실행 연결
  - [ ] 비용·성공률 CloudWatch 대시보드 구축

**위임(Delegation):** `sagemaker-spot-training` (존재) — 본 스킬이 Phase 5 리포트 생성 후 `sagemaker-spot-training` 스킬로 how-to를 위임한다. 세부 구현(config.yaml 구조, launch 스크립트, 쿼터 자동 확인)은 해당 스킬에서 다룬다.

**Citations:**
- [AWS Docs — SageMaker Managed Spot Training](https://docs.aws.amazon.com/sagemaker/latest/dg/model-managed-spot-training.html)
- [AWS Docs — Spot placement scores](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-placement-score.html)
- [Insight #1] — 리전별 placement score 편차
- [Insight #5] — 3분 시작 오버헤드
- [Insight #6] — GPU Spot 쿼터 관리
- [Insight #13] — 배치 사이즈 × LR × 하드웨어 상호작용
- [Insight #15] — 229s/$0.16 검증 사례
- [tradeoffs-compute.md §2] — SageMaker Managed Spot 정량 한계
- [tradeoffs-spot.md §4] — HUGI 원칙

---

### Pattern 1.2: EMR → AWS Batch + Spot (SPOT_CAPACITY_OPTIMIZED)

**적용 조건** (when to use):
- 분산 ETL / Spark / 배치 처리 워크로드
- retryable · fault-tolerant 작업 단위
- 작업 단위 실행 시간 15분 초과 (Lambda 불가)
- 기존 EMR step 인터페이스에 강하게 의존하지 않음

**AS-IS:**
```text
[Data event / cron]
       |
       v
[EMR cluster (상시 or on-demand)]
  ├─ Master (m5.xlarge)
  ├─ Core × N
  └─ Task × M
       │
       ├─▶ [S3 input] ─▶ [Spark job] ─▶ [S3 output]
       └─ cluster idle 대기 시간 과금
```

**TO-BE:**
```text
[EventBridge / Step Functions]
       |
       v
[AWS Batch job queue]
  ├─ Compute env: Fargate/EC2 Spot (SPOT_CAPACITY_OPTIMIZED)
  ├─ Compute env: On-Demand (fallback queue)
  └─ retryStrategy.attempts ≥ 2, evaluateOnExit
       │
       ├─▶ [S3 input] ─▶ [Container job] ─▶ [S3 output]
       └─ 과금 = 컨테이너 실행 시간만
```

**핵심 변경:**
- 클러스터 상시 유지 → 작업 단위 compute environment 자동 프로비저닝
- `SPOT_CAPACITY_OPTIMIZED` 할당 전략으로 인터럽트 최소화 [AWS Docs — Batch Spot]
- Spot compute-env 우선 + On-Demand fallback 큐의 2단 구성 [AWS Docs]
- Spark 로직은 컨테이너화 (EMR Serverless 또는 AWS Batch on ECS/Fargate)

**트레이드오프:**
- **장점**: 클러스터 idle 과금 제거, Spot 절감, 작업 단위 독립 리소스
- **단점 1**: **EMR step 인터페이스 상실** — 기존 Oozie/Airflow-on-EMR 워크플로 Step Functions로 재작성
- **단점 2**: Hive metastore / HDFS 의존 job은 S3/Glue Catalog로 재아키텍처 필요
- **단점 3**: `BEST_FIT` 전략은 Spot 인터럽트률이 높아 부적합 — `SPOT_CAPACITY_OPTIMIZED`만 Spot 권장 [AWS Docs]
- **단점 4**: SIGTERM 핸들러·체크포인트가 컨테이너 이미지 레벨에서 준비돼야 함 [AWS Docs]

**비용 범위** (예시, 검증 사례 출처 필수):
- 본 패턴은 autoresearch/openclaw가 직접 검증한 워크로드는 아니며, Spot 절감 원칙만 공유한다. 구체 벤치마크는 없음 — `[Case: autoresearch]`의 Spot HUGI 원칙을 동일 전제로 적용한다.
- 참고: 4-병렬 autoresearch 실험 $0.066 (Batch-유사 패턴의 parallel 특성 입증) [Case: autoresearch] [Insight #8]

**이행 체크리스트 스켈레톤:**
- [ ] **Stage 0 (사전 준비)**:
  - [ ] Spark 잡의 상태 저장성 검토 — HDFS 의존 제거, S3 중심 설계
  - [ ] 컨테이너 이미지 빌드 (Spark + 의존성 + SIGTERM 핸들러)
  - [ ] Spot 쿼터 / 인스턴스 타입 다양화 확인
  - [ ] Glue Data Catalog 이전 (Hive metastore 대체)
- [ ] **Stage 1 (저위험 검증)**:
  - [ ] 소규모 데이터셋으로 Batch job 제출
  - [ ] `SPOT_CAPACITY_OPTIMIZED` 할당 전략 적용 확인
  - [ ] `retryStrategy.attempts = 2-3` + `evaluateOnExit` 테스트
- [ ] **Stage 2 (파일럿)**:
  - [ ] EMR과 병렬 운영, 결과 동등성 비교
  - [ ] 인터럽트 시나리오 검증 (FIS 또는 Spot capacity reclaim 대기)
  - [ ] Spot 큐 / On-Demand 큐 큐 우선순위 검증
- [ ] **Stage 3 (전환)**:
  - [ ] EMR 클러스터 단계적 축소
  - [ ] Step Functions로 job chain 재배선
  - [ ] 비용 대시보드 (Spot 절감률, retry 횟수)

**위임(Delegation):** 없음 — 전용 스킬 미존재. 구현 단계는 [AWS Docs — AWS Batch with Spot](https://docs.aws.amazon.com/batch/latest/userguide/spot.html) 참고.

**Citations:**
- [AWS Docs — AWS Batch with Spot](https://docs.aws.amazon.com/batch/latest/userguide/spot.html)
- [AWS Docs — Batch allocation strategies](https://docs.aws.amazon.com/batch/latest/userguide/allocation-strategies.html)
- [AWS Docs — EMR Serverless (대안)](https://docs.aws.amazon.com/emr/latest/EMR-Serverless-UserGuide/what-is-emr-serverless.html)
- [tradeoffs-compute.md §5] — Batch 할당 전략 비교
- [tradeoffs-spot.md §5] — Spot Do/Don't
- [Insight #8] — 병렬 실행의 효율

---

### Pattern 1.3: Cron on EC2 → EventBridge Scheduler + Lambda / Batch

**적용 조건** (when to use):
- 주기 실행 작업 (daily/hourly/rate expression)
- EC2 crontab 의존 레거시 스케줄 작업
- 작업 단위 실행 시간:
  - **<15분 → Lambda** (동시성 1,000 기본 수용 가능)
  - **≥15분 → AWS Batch** (Pattern 1.2 참조)
- 상태를 외부(S3/DynamoDB/RDS)에 위임 가능

**AS-IS:**
```text
[EC2 (t3.medium 상시)]
  └─ /etc/crontab:
       0 2 * * *  run-daily-etl.sh
       */15 * * * *  health-check.sh
       0 0 * * 0  weekly-report.sh

  월 ~$30 EC2 + idle 대부분
```

**TO-BE:**
```text
[EventBridge Scheduler]
  ├─ rule: cron(0 2 * * ? *) ─▶ [Lambda: daily-etl]
  ├─ rule: rate(15 minutes) ──▶ [Lambda: health-check]
  └─ rule: cron(0 0 ? * SUN *) ▶ [Batch job: weekly-report]  (>15분)

  과금 = 실행 시간만 (Lambda) · 컨테이너 시간만 (Batch)
```

**핵심 변경:**
- crontab syntax → EventBridge rate/cron expression 변환 [AWS Docs — EventBridge Scheduler]
- 짧은 잡은 Lambda, 긴 잡은 Batch로 분기 (15분 상한 기준) [tradeoffs-compute.md §1.2]
- EC2 상시 인스턴스 제거 — zero-idle 달성
- 로그·메트릭은 CloudWatch로 통합 (로컬 로그 파일 의존 제거)

**트레이드오프:**
- **장점**: EC2 고정비 제거, 작업 격리 (한 잡 실패가 다른 잡에 영향 없음), 자동 재시도·DLQ 내장
- **단점 1**: cron syntax 일부 차이 — AWS cron은 6필드 (`분 시 일 월 요일 년`), 표준 5필드와 다름. `?` 플레이스홀더 사용 규칙. [AWS Docs]
- **단점 2**: 15분 초과 작업은 Lambda 불가 → Step Functions 분해 또는 Batch로 위임 [AWS Docs — Lambda quotas]
- **단점 3**: 잡 간 암묵적 공유 상태(로컬 파일, 환경변수)를 S3/DynamoDB로 외부화 필요 (Serverless Lens 원칙 3)
- **단점 4**: `EventBridge Scheduler`는 scheduled rules의 후계 — 신규 설계는 Scheduler 선택 (혼동 주의) [AWS Docs]

**비용 범위** (예시, 검증 사례 출처 필수):
- openclaw의 EventBridge scheduled pre-warming: 월 **~$0.07** 추가 비용으로 first-response 콜드스타트 페널티 제거 [Case: openclaw] [Insight #O3]
- 본 스케줄링 패턴 자체는 autoresearch/openclaw가 직접 벤치마크하지 않았으나, openclaw의 $0.07/월 수치는 EventBridge + Lambda 조합의 참조 단가로 활용 가능.

**이행 체크리스트 스켈레톤:**
- [ ] **Stage 0 (사전 준비)**:
  - [ ] 현재 crontab 인벤토리 작성 (스케줄, 실행 시간, 의존성)
  - [ ] 각 작업을 Lambda / Batch 중 어느 쪽에 배치할지 15분 기준 분류
  - [ ] 로컬 파일·환경 의존성을 S3/DynamoDB로 외부화 설계
  - [ ] IAM 역할 최소 권한 정의 (작업별 격리)
- [ ] **Stage 1 (저위험 검증)**:
  - [ ] 단일 저위험 작업을 EventBridge Scheduler + Lambda로 이전
  - [ ] 실행 로그·실패 알람 검증
  - [ ] cron expression 표기 차이 확인 (AWS 6필드 규칙)
- [ ] **Stage 2 (파일럿)**:
  - [ ] 상위 5개 작업 이전, EC2 crontab은 주석 처리 (이중 실행 방지)
  - [ ] 장시간(>15분) 작업을 Batch로 분리 (Pattern 1.2 적용)
  - [ ] DLQ·재시도·알람 연결 확인
- [ ] **Stage 3 (전환)**:
  - [ ] 잔여 작업 이전 완료 후 EC2 terminate
  - [ ] 유지보수용 운영 대시보드 (스케줄러 실행 성공률, 지연)

**위임(Delegation):** 없음 — 전용 스킬 미존재. 구현 단계는 [AWS Docs — EventBridge Scheduler](https://docs.aws.amazon.com/scheduler/latest/UserGuide/what-is-scheduler.html) 및 [AWS Docs — Lambda Scheduled Events](https://docs.aws.amazon.com/lambda/latest/dg/services-cloudwatchevents.html) 참고.

**Citations:**
- [AWS Docs — EventBridge Scheduler](https://docs.aws.amazon.com/scheduler/latest/UserGuide/what-is-scheduler.html)
- [AWS Docs — EventBridge cron/rate expressions](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html)
- [AWS Docs — Lambda quotas](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html)
- [tradeoffs-compute.md §1.2] — Lambda 15분 상한
- [tradeoffs-event-driven.md §1] — EventBridge Scheduler vs Scheduled rules
- [Insight #O3] — EventBridge scheduled pre-warming

---

## 3. Anti-patterns

**A1. Spot 인터럽트 불가 워크로드에 Spot 강제 적용**
- 규정 준수·무정지 요구 배치(금융 정산, 규제 보고)는 Spot 부적합
- AWS Batch 문서: 프로덕션 API·데이터베이스·엄격 SLA는 Spot 제외 워크로드로 명시 [AWS Docs — Batch with Spot]

**A2. 체크포인트 없이 MaxWait 60분 초과 시도**
- SageMaker 내장·마켓플레이스 알고리즘은 체크포인트 미사용 시 `MaxWaitTime ≤ 3600s` 강제
- 체크포인트 없이 장시간 Spot 잡을 던지면 2회 인터럽트 후 `Stopped: MaxWaitTimeExceeded`로 종료되고 BillableTime만 과금되는 worst case 발생 [AWS Docs — SageMaker]

**A3. 단일 AZ 고정 with Spot**
- 용량 편차가 리전·AZ별로 극단적이어서 단일 AZ는 Spot 가용성의 안티패턴 [Insight #1]
- 다중 AZ + 다중 인스턴스 타입 + ASG / SPOT_CAPACITY_OPTIMIZED의 3종 세트가 최소 요건 [tradeoffs-spot.md §5]

**A4. `BEST_FIT` 할당 전략 + Spot**
- `BEST_FIT`은 최소 가용 인스턴스만 선택 → 인터럽트률 증가 [AWS Docs — Batch allocation strategies]
- Spot 워크로드의 기본 권장은 `SPOT_CAPACITY_OPTIMIZED` [tradeoffs-compute.md §5.1]

**A5. 시작 오버헤드를 무시한 초단기 잡 양산**
- SageMaker 잡당 ~3분 오버헤드 → 5분 잡은 60%가 오버헤드 [Insight #5]
- 단일 잡에 실험 병합 또는 warm pool로 분할 비용 절감 필요

**A6. 최대가(max price) 수동 지정**
- 최대가를 On-Demand 상한보다 낮게 지정 시 인터럽트 빈도 증가 → 기본값(On-Demand 상한) 유지가 최선 [AWS Docs — EC2 Spot interruptions] [tradeoffs-spot.md §5]

---

## 4. Citations

- [AWS Docs — SageMaker Managed Spot](https://docs.aws.amazon.com/sagemaker/latest/dg/model-managed-spot-training.html)
- [AWS Docs — AWS Batch Spot](https://docs.aws.amazon.com/batch/latest/userguide/spot.html)
- [AWS Docs — Batch allocation strategies](https://docs.aws.amazon.com/batch/latest/userguide/allocation-strategies.html)
- [AWS Docs — EventBridge Scheduler](https://docs.aws.amazon.com/scheduler/latest/UserGuide/what-is-scheduler.html)
- [AWS Docs — Lambda quotas](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html)
- [AWS Docs — EC2 Spot interruptions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-interruptions.html)
- [AWS Docs — Spot placement scores](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-placement-score.html)
- [AWS Docs — EMR Serverless](https://docs.aws.amazon.com/emr/latest/EMR-Serverless-UserGuide/what-is-emr-serverless.html)
- [Case: autoresearch] — 48 실험 $3.94, H100 229s $0.16
- [Insight #1, #5, #6, #7, #8, #13, #15] — autoresearch 번호화 인사이트
- [Insight #O3] — openclaw EventBridge scheduled pre-warming
- Cross-refs: [tradeoffs-compute.md §1.2, §2, §5], [tradeoffs-spot.md §4, §5]
