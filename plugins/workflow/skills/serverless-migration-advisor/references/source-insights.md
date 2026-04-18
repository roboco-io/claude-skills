> **Snapshot date**: 2026-04-18
> **Numbering rule**: autoresearch insights are `#1-#15` (stable). openclaw principles are prefixed `#O1-#O6`. Future additions only extend (never renumber).
> **Description**: 번호화된 검증 인사이트 (Insight #N 인용 대상)

# Source Project Insights

본 파일은 **인용 앵커**다. 다른 references와 SKILL.md, 그리고 스킬이 생성하는 리포트는 이 번호를 통해 검증 근거를 추적한다.

## From serverless-autoresearch

Source: `/Users/dohyunjung/Workspace/roboco-io/research/serverless-autoresearch/docs/insights.md` @ commit `5435b374`

### Insight #1 — Spot Capacity Varies Dramatically by Region

동일 인스턴스 타입(g7e)이 리전별로 Spot placement score 1 (거의 불가능, 30분+ 대기)에서 9 (즉시 할당, ~2분 시작)까지 극단 편차를 보였다. us-west-2는 1-2, us-east-1은 9. 리전을 선택하기 전 `aws ec2 get-spot-placement-scores` 실행은 사실상 필수 절차다.

- **Tier**: 1 (배치·훈련)
- **Cited by**: tradeoffs-spot.md §1, patterns-tier1-batch.md Pattern 1.1, case-study-autoresearch.md

### Insight #2 — Larger Instances Can Be Cheaper on Spot

g7e.8xlarge ($0.93/hr)가 g7e.2xlarge ($0.94-$1.82/hr)보다 싼 경우가 us-west-2에서 관측됨. 큰 인스턴스는 Spot 수요가 낮아 가격이 역전된다. "사이즈가 크면 더 비싸다"는 가정을 금지하고 Spot price history를 직접 확인해야 한다.

- **Tier**: 1 (배치·훈련)
- **Cited by**: tradeoffs-spot.md §1, patterns-tier1-batch.md

### Insight #3 — DEVICE_BATCH_SIZE ≠ Token Throughput (hardware-dependent — see also #13)

TOTAL_BATCH_SIZE를 고정한 채 DEVICE_BATCH_SIZE만 64→128로 2배 늘려도 토큰 처리량은 불변(gradient accumulation step이 4→2로 감소할 뿐). L40S+SDPA에서는 오히려 val_bpb가 1.065→1.081로 악화. 동일 스왑이 H100+FA3에서는 개선된다는 점(#13)과 함께 "하드웨어별 상반된 방향" 패턴을 보여주는 사례.

- **Tier**: 1 (배치·훈련 — 훈련-특화)
- **Cited by**: case-study-autoresearch.md, source-insights.md #13 (cross-ref)

### Insight #4 — Flash Attention 3 is GPU-Architecture Specific

FA3 pre-compiled 커널은 Hopper (sm_90) / Ampere (sm_80/86)만 지원. Ada Lovelace (sm_89, L40S)는 미지원으로 런타임 CUDA 오류. 해결책은 compute capability 검사 + PyTorch SDPA fallback (SDPA ~20% MFU vs FA3 ~40% MFU — 효율은 절반).

- **Tier**: 1 (배치·훈련)
- **Cited by**: case-study-autoresearch.md (하드웨어 주의), patterns-tier1-batch.md

### Insight #5 — SageMaker Startup Overhead is Significant

SageMaker Training Job당 ~3분 startup overhead (인스턴스 할당 + 컨테이너 pull + 데이터 다운로드 + pip install). 5분 훈련 잡이면 **60%가 오버헤드**. 완화 방법 3가지: (1) 멀티-GPU 인스턴스로 N 실험을 1 잡에 합침, (2) pip 대신 Docker 이미지에 의존성 사전 빌드, (3) SageMaker warm pool (단, 추가 비용).

- **Tier**: 1 (배치·훈련)
- **Cited by**: tradeoffs-compute.md §2, patterns-tier1-batch.md Pattern 1.1, case-study-autoresearch.md

### Insight #6 — Quota Management is a First-Class Concern

GPU Spot 쿼터는 신규 인스턴스 타입에 대해 기본값 0. g7e는 분 단위 자동 승인되지만 p5/p6은 수동 검토 (CASE_OPENED, 며칠 소요). 다중 리전에서 쿼터를 사전 요청하는 것이 마이그레이션 블록 방지의 전제 조건.

- **Tier**: 1 (배치·훈련)
- **Cited by**: tradeoffs-compute.md §2, patterns-tier1-batch.md Pattern 1.1 Stage 0 체크리스트

### Insight #7 — SageMaker Profiler Doesn't Support All Instance Types

`ml.g7e` 인스턴스는 잡 생성 시 `ValidationException: Profiler is currently not supported` 오류. PyTorch Estimator에 `disable_profiler=True` 설정으로 해결.

- **Tier**: 1 (배치·훈련, 운영 원칙)
- **Cited by**: patterns-tier1-batch.md Pattern 1.1 Stage 0 체크리스트

### Insight #8 — The Parallel Evolution Approach Works

파이프라인이 candidate 생성, 병렬 Spot 잡 제출, 결과 수집, best 선정까지 autonomous 동작을 검증. 4 병렬 실험이 총 $0.066, ~10분 wall clock (us-west-2 Spot wait time 제외) — parallel autonomous HPO가 실제로 cost-efficient함을 입증.

- **Tier**: 1 (배치·훈련)
- **Cited by**: patterns-tier1-batch.md Pattern 1.2 (병렬 Batch), case-study-autoresearch.md

### Insight #9 — PyArrow Version Matters

SageMaker DLC에는 pyarrow 23.x가 설치되지만 로컬 환경이 구버전이면 parquet 파일 읽기 시 `Repetition level histogram size mismatch`. `requirements-train.txt`에 `pyarrow>=21.0.0` 강제가 해결책.

- **Tier**: 1 (배치·훈련, 운영 원칙)
- **Cited by**: case-study-autoresearch.md (하드웨어·버전 주의)

### Insight #10 — config.yaml Should Never Be in Git

config.yaml에 AWS role ARN, 프로필, 리전 등 환경 특화·민감 정보 포함. gitignore 처리 + `config.yaml.example` 템플릿 제공이 원칙.

- **Tier**: 1 (배치·훈련, 운영 원칙)
- **Cited by**: case-study-autoresearch.md (운영 원칙), patterns-tier1-batch.md (Stage 0 IAM)

### Insight #11 — Spot GPUs Are Valid Proxies for Large-Scale Training

연구 확인: cheaper GPU (L40S)에서의 HPO가 expensive GPU (H100)로 잘 전이됨. 전이되는 것 — optimizer 선택 (Muon vs AdamW) 상대 순위, 아키텍처 결정 (깊이·너비·어텐션), LR schedule 모양 (코사인, warmup 비율), 상대 하이퍼파라미터 순위. 전이되지 않는 것 — 절대 val_bpb, 최적 batch size (VRAM 의존), memory-dependent 최적화 (FA3·FP8), 절대 LR 값. Phase 1은 Spot L40S로 $0.04/실험 수준, Phase 2는 H100에서 final run.

- **Tier**: 1 (배치·훈련)
- **Cited by**: case-study-autoresearch.md (인터럽트율 설명과 결합)

### Insight #12 — DEVICE_BATCH_SIZE ≠ More Training (L40S-specific; reversed on H100)

L40S+SDPA: BS 64→128 스왑이 val_bpb 악화 (1.065→1.081). 오로지 gradient accumulation step을 4→2로 줄일 뿐 total token은 불변. H100+FA3: 동일 스왑이 val_bpb 개선 (1.0016→0.9951, -0.0065). 하드웨어+어텐션 커널의 조합이 batch size 방향을 뒤집는다. L40S에서는 TOTAL_BATCH_SIZE를 늘려야 throughput 확보.

- **Tier**: 1 (배치·훈련)
- **Cited by**: case-study-autoresearch.md (하드웨어별 튜닝 주의), source-insights.md #13

### Insight #13 — Batch Size × LR × Hardware Interact — Evolved LRs Can Be BS-Specific

H100 BS=64에서 5-세대 진화로 찾은 "최적" LR (EMBEDDING 0.7091→0.6433, UNEMBEDDING 0.003369→0.004206)을 BS=128에 적용하자 **악화**. 원본 L40S-진화 LR (0.7091/0.003369)을 BS=128과 조합하면 val_bpb 0.9951 (upstream 0.998 이하) 달성. Effective LR은 BS에 스케일한다 — Phase-2의 LR 조정이 BS=64의 noisy gradient를 보상하던 것이 BS 배증 시 overcorrection이 됨. 규칙: LR과 BS는 **함께** 진화, 하드웨어·BS 변경 시 LR 재방문 필수. **비용 레슨**: 고정한 가정(BS) 점검이 $0.16 1회 실험에 -0.0065 val_bpb, 20회 LR 탐색 $3에 -0.0014 — **100× cost-efficient**.

- **Tier**: 1 (배치·훈련)
- **Cited by**: case-study-autoresearch.md, patterns-tier1-batch.md Pattern 1.1 트레이드오프

### Insight #14 — Cheap-GPU-Evolved LRs Transfer to Expensive GPUs — Sometimes Better Than Re-Evolving

L40S Spot ($0.40, 24 실험)에서 찾은 LR을 H100에 BS=128 upstream으로 적용하여 **upstream baseline 이하** 달성 (0.9951 < 0.998). Phase-2 H100-native LR 재진화는 오히려 악화 (잘못된 BS 주변에서 탐색). 하이퍼파라미터 *순위*는 하드웨어-독립, *절대 값*은 BS와 더 강하게 결합. 규칙: 값싼 Spot GPU (L40S/A10G)로 Phase-1 LR/아키텍처 탐색, expensive GPU로의 final run은 **cheap-GPU-evolved config 그대로** 먼저 시도 — 강한 시작점이며 종종 최종 답.

- **Tier**: 1 (배치·훈련)
- **Cited by**: case-study-autoresearch.md (phase 1→2 전이 서사)

### Insight #15 — Serverless Spot Can Match or Beat Dedicated H100 Results at 44–150× Lower Cost

Karpathy upstream H100 autoresearch (val_bpb ~0.998)을 **단일 ml.p5.4xlarge Spot run 229초, ~$0.16**로 재현·소폭 상회 (0.9951). 비교표: Karpathy H100 8h continuous, val_bpb ~0.998, $7-24 vs 이 실험 H100 Spot 229s billable, val_bpb 0.9951, $0.16 — **비용 44-150× 절감, wall clock ~24× 단축**. 단서: 단일 실행 값으로 통계적 우위 주장은 재실행 ±σ 필요. 다만 보고값을 **1-2% 비용**으로 매치·상회한 것 자체가 의미있는 서버리스-ML 결과. 규칙: <30분 잡 재현에서 Spot+HUGI는 strict improvement; 그 이상은 인터럽트 리스크 시작.

- **Tier**: 1 (배치·훈련, 핵심 서사)
- **Cited by**: case-study-autoresearch.md, tradeoffs-compute.md §2, patterns-tier1-batch.md Pattern 1.1 (비용 범위), tradeoffs-spot.md §4 (HUGI)

## From serverless-openclaw

Source: github.com/serithemage/serverless-openclaw (alpha), README 2026-04-18 snapshot

### Insight #O1 — Lambda Container + Fargate Spot dual compute fallback

기본 Lambda Container로 zero-idle · 1.35초 cold start, 15분 초과·고부하 세션은 ECS Fargate Spot fallback. 컴퓨트 비용 **70% 절감** 달성. Fargate Spot의 자동 On-Demand fallback이 없다는 AWS 문서 제약을 **Lambda를 primary로 두는 이중 구성**으로 우회.

- **Tier**: 2 (상시형 API)
- **Cited by**: patterns-tier2-api.md Pattern 2.1/2.2, tradeoffs-compute.md §3, case-study-openclaw.md

### Insight #O2 — API Gateway over ALB

ALB 고정비 **$18-25/월**을 API Gateway pay-per-use로 대체. 저트래픽·버스트 패턴에서 결정적 이익 — idle 시 $0, 요청당 $3.5/M (REST) 또는 $1.0/M (HTTP API). 규제·L7 라우팅 요구가 없다면 기본 선택.

- **Tier**: 2 (상시형 API)
- **Cited by**: patterns-tier2-api.md Pattern 2.1, case-study-openclaw.md

### Insight #O3 — EventBridge scheduled pre-warming

액티브 시간대에만 EventBridge Scheduler cron으로 Lambda를 주기 호출 → **0초 first-response** 달성. 24/7 Provisioned Concurrency (월 ~$15+) 대신 월 **~$0.07** 추가만으로 cold start 페널티 제거. 비액티브 시간에는 idle 유지하여 zero-idle 원칙 보존.

- **Tier**: 2 (상시형 API)
- **Cited by**: patterns-tier2-api.md Pattern 2.1, patterns-tier1-batch.md Pattern 1.3 (수치 참조), case-study-openclaw.md

### Insight #O4 — S3/DynamoDB session persistence for stateless Lambda

상태 없는 Lambda에서 **세션 지속성** 확보. DynamoDB가 session index·메타데이터 (On-Demand 모드로 zero-idle), S3가 payload·대화 이력 (동시성 제어). Serverless Lens 원칙 3 "Share nothing"을 실현하는 표준 패턴.

- **Tier**: 2 (상시형 API)
- **Cited by**: patterns-tier2-api.md Pattern 2.3, tradeoffs-data-layer.md §2, case-study-openclaw.md

### Insight #O5 — Free-tier first cost target

개인 사용 **$1-2/월** (Free Tier 내 $0.23) 목표. 모든 구성 요소 (API Gateway, Lambda, DynamoDB On-Demand, S3, CloudFront, EventBridge)에 **zero-idle + per-request 청구** 원칙 적용한 결과. 사이드 프로젝트·개인 도구의 비용 타겟 근거.

- **Tier**: 2 (상시형 API)
- **Cited by**: case-study-openclaw.md, tradeoffs-compute.md §1 (Lambda zero-idle 근거)

### Insight #O6 — CloudFront + S3 for web UI

정적 웹 UI (React SPA · Next.js export)를 S3 버킷 + CloudFront 배포로 서빙. EC2/Lambda 런타임 없이 **0 idle 비용** 달성. Lambda+API Gateway의 동적 경로와 분리하여 static vs dynamic 경로 비용 구조를 분리.

- **Tier**: 2 (상시형 API)
- **Cited by**: patterns-tier2-api.md (정적 UI 포함 패턴), case-study-openclaw.md
