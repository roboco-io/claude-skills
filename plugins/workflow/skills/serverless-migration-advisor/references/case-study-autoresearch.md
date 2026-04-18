> **Snapshot date**: 2026-04-18
> **Source**: github.com/roboco-io/serverless-autoresearch @ commit 5435b374 (RESEARCH.md §10.1 기록)
> **Local path**: /Users/dohyunjung/Workspace/roboco-io/research/serverless-autoresearch/
> **Tier**: 1 (배치·훈련)
> **Description**: Tier 1 검증 사례 — serverless-autoresearch

# Case Study — serverless-autoresearch

본 케이스는 본 스킬의 **Tier 1 (배치·훈련) 인용 앵커**다. 리포트 Tradeoff Dossier, 비용 범위, 체크리스트 근거는 이 파일과 [source-insights.md](source-insights.md) #1-#15로 역추적된다.

## Headline 숫자 (인용 가능)

- **48 Spot 실험 / 총비용 $3.94** — autonomous HPO 파이프라인 전체 비용
- **H100 Spot 229초 / $0.16** (상용 비교 $7-24 / 8h) — 44-150× 저렴한 재현
- **val_bpb 0.9951** — Karpathy upstream ~0.998 재현·소폭 상회
- **Spot 인터럽트율 H100 ~5%** (실측) — 체크포인트 기반 재시도로 최종 성공률 100%
- **4 병렬 실험 $0.066 / ~10분 wall clock** — parallel pipeline cost 검증
- **리전별 placement score 1↔9** — 동일 인스턴스 타입에서도 30분+ 대기 vs ~2분 시작의 극단 편차

## 목표 워크로드

- 소규모 언어 모델 훈련 자동화 (autoresearch 패턴) — Karpathy nanoGPT 기반
- 48개 config 병렬 비교 실험 (Muon/AdamW, LR/BS 진화)
- Phase 1 L40S Spot 탐색 + Phase 2 H100 Spot 검증의 2단 파이프라인

## 아키텍처 요약

```text
users → batch_launcher.py → N개 SageMaker Managed Spot training jobs
                               ├─ S3 (input data, checkpoints)
                               ├─ CloudWatch (metrics, logs)
                               └─ result_collector.py (post-processing)
```

핵심 구성 요소:

- **Launcher**: `batch_launcher.py` — boto3 `sagemaker.PyTorch` Estimator로 N개 잡을 병렬 제출. `MaxWaitTime > MaxRuntime` 강제.
- **Spot 활용**: SageMaker Managed Spot (BillableTime = Training 시간만). `(1 - BillableTime/TrainingTime) × 100`으로 절감률 계산.
- **Checkpointing**: S3↔컨테이너 로컬 경로 자동 동기화 (SageMaker 내장). 인터럽트 후 자동 재시작.
- **Collector**: `result_collector.py` — 잡 완료 이벤트 수신 후 결과 집계·최적 config 선정.
- **리전 선택**: `aws ec2 get-spot-placement-scores`로 사전 평가한 리전 고정.

## 이 스킬이 인용 가능한 범위 (Quotable statements)

각 항목은 해당 context에서 리포트 Tradeoff Dossier 또는 비용 범위 칸에 **직접 인용** 가능:

- "이 워크로드 패턴은 상용 대비 **20-100× 저렴하게 재현** 가능 — [Case: autoresearch]"
- "H100 Spot 인터럽트율 ~5%로 관측됨 (48회 실험, 체크포인트 기반 재시도로 최종 성공률 100%) — [Case: autoresearch + Insight #11]"
- "SageMaker startup overhead ~3분. 5분 작업에는 60% 오버헤드 — 배치 누적 또는 짧은 작업에는 비효율 — [Insight #5]"
- "리전 placement score 1-2에서는 30분+ 대기, 9에서는 ~2분 시작 — 리전 선택이 인스턴스 크기보다 중요 — [Insight #1]"
- "큰 인스턴스가 Spot 시장에서 **더 저렴한 경우가 존재** (g7e.8xlarge < g7e.2xlarge in us-west-2) — [Insight #2]"
- "Phase 1 L40S에서 찾은 LR을 H100에 그대로 적용하여 upstream baseline 이하 달성 — 값싼 GPU에서의 튜닝이 전이 가능 — [Insight #14]"
- "단일 가정 점검(BS 고정 해제)이 20회 탐색보다 **100× 비용 효율** — [Insight #13]"

## 적용 가능 워크로드

- 배치 ML 훈련 (체크포인트 지원 필수)
- 하이퍼파라미터 튜닝 병렬 실행 (SageMaker HPO Managed Spot 호환)
- Offline batch inference — 결과가 S3에 고정 저장되는 형태
- 재현 가능한 실험 파이프라인 (연구·논문 재현)
- 4~48 병렬 수준의 autonomous ML 파이프라인

## 적용 불가

- **단일 긴 연속 훈련** (체크포인트 오버헤드 비효율 · 3분 startup × 다회 재시작)
- **초저지연 추론** (Lambda 또는 Fargate 필요 — SageMaker Training Job은 endpoint가 아님)
- **Real-time streaming** (Kinesis/Managed Streaming으로 분리 필수)
- **FA3 의존 워크로드 on L40S/Ada** — 하드웨어 지원 범위 주의 [Insight #4]
- **체크포인트 불가능한 알고리즘** — MaxWait 3600s 이내로 압축되지 않으면 SageMaker Managed Spot 부적합

## 하드웨어·리전별 주의사항 (Tier 1 특화)

- **쿼터는 First-class concern** — GPU Spot 기본 0, p5/p6는 수동 검토 (며칠 소요) [Insight #6]
- **g7e는 Profiler 미지원** — `disable_profiler=True` 필수 [Insight #7]
- **PyArrow 버전 불일치** — DLC 23.x, 로컬이 더 낮으면 parquet 읽기 실패. `pyarrow>=21.0.0` [Insight #9]
- **config.yaml 절대 git 커밋 금지** — 역할 ARN·프로필·리전 포함 [Insight #10]

## 관련 파일 참조

- 전체 실험 데이터: `experiments/003-h100-comparison/results-summary.md`
- 원본 인사이트: `docs/insights.md` 또는 본 스킬의 [source-insights.md](source-insights.md) §Insight #1~#15
- 리전 선택 가이드: `docs/spot-capacity-guide.md`
- 비교 분석: `docs/comparison-report.md` (Sequential vs Parallel Spot)
- Source commit: `5435b374fb5daae5eee95e3e8eb9292caacf94f8`

## Cross-references (내부)

- [patterns-tier1-batch.md](patterns-tier1-batch.md) Pattern 1.1 (SageMaker Spot 이행) — 본 케이스가 근거
- [tradeoffs-compute.md](tradeoffs-compute.md) §2 (SageMaker Managed Spot)
- [tradeoffs-spot.md](tradeoffs-spot.md) §1 (placement scores), §4 (HUGI 원칙)
- [source-insights.md](source-insights.md) #1-#15 — 번호화된 인사이트
