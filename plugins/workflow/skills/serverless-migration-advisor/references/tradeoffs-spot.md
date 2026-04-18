> **Snapshot date**: 2026-04-18
> **Description**: Spot 용량·인터럽트·HUGI·billable 정의

# Spot Tradeoffs

AWS Spot를 활용한 이행 시 공통 고려사항. 서비스별 특화(Fargate Spot / EC2 Spot / SageMaker Managed Spot / Batch Spot)는 [tradeoffs-compute.md](tradeoffs-compute.md) 참조.

## 1. Placement scores — 리전 선택이 첫 번째 비용 결정

**원칙**: 같은 인스턴스 타입이라도 리전마다 Spot 용량은 극단적으로 다름. 실측 사례로 score 1-2 (us-west-2) vs score 9 (us-east-1)가 존재한다. [Insight #1]

### 1.1 명령 예시

```bash
# 여러 리전 점수 비교 (한 번에 봐야 결정 가능)
for region in us-east-1 us-east-2 us-west-2 eu-west-1 ap-northeast-1; do
  echo -n "$region: "
  aws ec2 get-spot-placement-scores \
    --instance-types g7e.4xlarge \
    --target-capacity 1 \
    --single-availability-zone \
    --region-names $region \
    --region $region \
    --query "max_by(SpotPlacementScores, &Score).Score" \
    --output text 2>/dev/null
done
```

### 1.2 점수 해석 [AWS Docs — Spot placement scores]

| Score | 의미 | 의사결정 |
|-------|------|----------|
| 8-10 | 높은 가용성 | 진행 |
| 5-7 | 중간 | 진행하되 fallback 준비 |
| 3-4 | 낮음 | 대안 검토 또는 지연 수용 |
| 1-2 | 매우 낮음 | **리전 전환** |

### 1.3 실측 사례 — autoresearch [Insight #1]

| 리전 | 인스턴스 | 점수 | 결과 |
|------|----------|------|------|
| us-west-2 | ml.g7e.2xlarge/4xlarge | 1-2 | 30분+ "Starting" 정체 |
| us-east-1 | ml.g7e.2xlarge | 9 | 약 2분 내 할당 |

**교훈**: 30초의 CLI 조회가 30분+ 대기를 방지한다. [Case: autoresearch]

## 2. Interruption behaviors

EC2 Spot의 3가지 인터럽트 동작. Fargate Spot·SageMaker Managed Spot은 이 중 `terminate` 시맨틱만 노출된다. [AWS Docs]

| 동작 | 시맨틱 | 2분 경고 | 조건 |
|------|--------|----------|------|
| `terminate` | 인스턴스 종료 (기본) | 제공 | 항상 가능 |
| `stop` | EBS 보존, 재시작은 EC2만 | 제공 | **persistent request** |
| `hibernate` | RAM 보존, 복원 즉시 시작 | **없음** (즉시) | 패밀리·AMI 지원 필요 |

## 3. Interruption signals

### 3.1 2분 경고 이벤트 (EventBridge)

```json
{
  "detail-type": "EC2 Spot Instance Interruption Warning",
  "source": "aws.ec2",
  "detail": {
    "instance-id": "i-0abcd...",
    "instance-action": "terminate"
  }
}
```

Fargate Spot은 같은 EventBridge 이벤트(`ECS Task State Change` + `stopCode: "SpotInterruption"`)로 관측. [AWS Docs]

### 3.2 IMDSv2 메타데이터 (EC2 Spot)

```bash
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/spot/instance-action
# → {"action": "terminate", "time": "2026-04-18T10:00:00Z"}
```

권장 폴링 간격: **5초**. [AWS Docs]

### 3.3 Rebalance recommendation

2분 경고보다 **먼저** 발생하는 선제 신호. EventBridge `EC2 Instance Rebalance Recommendation` 이벤트 또는 IMDSv2 `rebalance` 엔드포인트로 수신. ASG와 결합하면 사실상 drain 여유가 2분 이상으로 확장된다. [AWS Docs]

## 4. HUGI 원칙 — Hurry Up and Get Idle

**핵심**: Spot에서 절감은 "wall clock을 줄이는" 것이 아니라 "과금되는 시간 자체를 줄이는" 것으로 달성된다.

### 4.1 Billable ≠ wall clock

SageMaker Managed Spot의 공식 정의: [AWS Docs]

```
절감률(%) = (1 - BillableTimeInSeconds / TrainingTimeInSeconds) × 100
```

- TrainingTime: Starting/Downloading 포함 잡 전체 wall clock
- BillableTime: **Training 구간만** 포함 (인터럽트 후 재개 시에도 training만 누적)

### 4.2 상시 서버 대비 수학적 근거

| 모델 | 24시간 중 활용률 | Billable |
|------|------------------|----------|
| 상시 EC2 (동일 작업을 8시간에 몰아 수행) | 33% | 24h × 1.0 (idle 포함) |
| Spot burst (8시간 수행 후 종료) | 33% | 8h × 0.3 (Spot 할인) = **약 10%** |

즉, 동일한 wall clock 결과(8h 작업)라도 HUGI 적용 시 과금 시간이 상시 서버의 **1/10 수준**이 된다. [Case: autoresearch] 229s H100 run이 $0.16에 멈추는 이유도 동일.

### 4.3 패턴 선택

- 예측 가능한 배치 → SageMaker Managed Spot (AWS가 billable 공식화)
- 예측 불가 이벤트 → Lambda (zero-idle이 기본 모델)
- 상시 + 스파이크 → Fargate + Fargate Spot 혼합 + API Gateway (ALB 고정비 제거) [Case: openclaw] [Insight #O2]

## 5. Do / Don't

| Do | Don't | 근거 |
|----|-------|------|
| 기본 max price (= On-Demand 가격 상한) 유지 | 수동으로 낮은 max price 지정 | 인터럽트 빈도 증가 [AWS Docs] |
| 다중 AZ + 다중 인스턴스 타입 + ASG | 단일 인스턴스 타입·단일 AZ 고정 | 용량 편차 [Insight #1] |
| ASG로 자동 교체 | 단독 인스턴스 장기 운영 | 교체 메커니즘 부재 [AWS Docs] |
| AWS FIS로 인터럽트 주입 사전 검증 | 운영 전 테스트 없이 배포 | [AWS Docs — FIS tutorial] |
| Rebalance recommendation 수신 시 proactive drain | 2분 경고만 기다림 | 선제 신호 미활용 [AWS Docs] |
| Fargate Spot = 서비스 단위 (`desiredCount ≥ 2`) | 단일 태스크 + Fargate Spot | 자동 fallback 없음 [Insight #O1] |
| 큰 인스턴스도 확인 | "크면 비쌀 것" 가정 | g7e.8xlarge $0.93 < g7e.2xlarge $1.82 사례 [Insight #2] |
| 체크포인트 반드시 활성화 (>5분 잡) | 체크포인트 없이 장시간 잡 | MaxWaitTime ≤ 1h 강제 [AWS Docs] |

## 6. 인터럽트 추적

### 6.1 CloudTrail `BidEvictedEvent`

EC2 Spot 인터럽트의 사후 감사 기록. 장애 분석·재시도 통계의 단일 소스. [AWS Docs]

### 6.2 EventBridge rule 예시

```json
{
  "source": ["aws.ec2"],
  "detail-type": ["EC2 Spot Instance Interruption Warning"]
}
```

```json
{
  "source": ["aws.ecs"],
  "detail-type": ["ECS Task State Change"],
  "detail": { "stopCode": ["SpotInterruption"] }
}
```

SNS 알람 + Lambda 자동 재시도 타겟으로 연결. [AWS Docs]

## 7. 워크로드별 Spot 적합도

AWS Batch 문서 기준 분류를 이행 관점으로 재배치. [AWS Docs]

| 워크로드 | Spot 적합 | 이유 |
|----------|-----------|------|
| 배치 ETL · 데이터 처리 | O | retry·멱등 설계가 자연스러움 [AWS Docs] |
| ML 훈련 · HPO | O | 체크포인트 → billable만 과금 [AWS Docs] · [Case: autoresearch] |
| CI/CD 빌드 | O | fault-tolerant · 재실행 저비용 [AWS Docs] |
| 렌더링·시뮬레이션 | O | 프레임/샘플 단위 분할 가능 [AWS Docs] |
| 상시 스테이트리스 API (primary) | △ | fallback 설계 필수 — openclaw는 Lambda primary + Fargate Spot fallback으로 해결 [Case: openclaw] [Insight #O1] |
| 프로덕션 데이터베이스 | X | 인터럽트 시 데이터 무결성 위험 [AWS Docs] |
| SLA 엄격한 사용자 대면 API | X | 2분 drain으로 부족 [AWS Docs] |
| 저지연 고정 컨슈머 | X | 재배치 비용이 과 [AWS Docs] |

---

*참고*: Spot 기반 워크로드의 구체적 how-to(지역 선정 스크립트, 쿼터 증액 명령)는 `sagemaker-spot-training` 스킬의 `references/spot-capacity-guide.md`로 위임된다.
