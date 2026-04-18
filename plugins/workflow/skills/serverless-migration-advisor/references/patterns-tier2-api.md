> **Snapshot date**: 2026-04-18
> **Tier**: 2 (always-on API/웹) — serverless-openclaw로 검증
> **Description**: 상시형 API·웹 이행 패턴

# Tier 2 Migration Patterns — Always-on API / Web

[Case: openclaw]로 검증된 Tier 2 이행. 세부 원칙은 RESEARCH.md §10.2.1 (O1-O6) 참조.

## 1. When Tier 2?

- 트래픽이 버스트 또는 주기적 — 상시 피크가 아니라 spiky 또는 업무시간 집중
- 요청 처리 시간 <5분 — Lambda 또는 Fargate Spot 수용 가능
- 콜드 스타트 허용 가능 — p99 <2s 수용하거나 SnapStart/Provisioned Concurrency/pre-warming으로 완화 가능
- 상시 DB·캐시 연결이 필수가 아니거나 RDS Proxy·DynamoDB로 대체 가능

## 2. Patterns

### Pattern 2.1: ALB + EC2 → API Gateway + Lambda

**적용 조건** (when to use):
- REST API · 짧은 요청/응답 (요청·응답 각 <6MB) [tradeoffs-compute.md §1.1]
- 실행 시간 <15분 [AWS Docs — Lambda quotas]
- Spiky / zero-idle 트래픽 (24시간 중 활용 구간이 일부)
- 웹소켓·gRPC streaming 등 long-lived 연결 불필요

**AS-IS:**
```text
[Client]
   |
   v
[ALB ($18-25/월 고정비)] ─▶ [EC2 ASG (최소 1대 상시)]
                                │
                                ├─▶ [RDS]
                                └─▶ logs/local state

  EC2 idle 시에도 ALB + EC2 고정비 과금
```

**TO-BE:**
```text
[Client]
   |
   v
[API Gateway (per-request 과금)] ─▶ [Lambda (zero-idle)]
                                       │
                                       ├─▶ [DynamoDB]
                                       └─▶ [S3 / RDS Proxy]

  호출 없으면 $0
```

**핵심 변경:**
- ALB 고정비 ($18-25/월) 제거 → API Gateway per-request 과금 [Case: openclaw] [Insight #O2]
- EC2 상시 → Lambda zero-idle
- 로컬 상태(session, file) → DynamoDB + S3 외부화 [Insight #O4]
- 데이터베이스 커넥션은 RDS Proxy 경유 (직접 연결 시 커넥션 폭주) [tradeoffs-data-layer.md §1]

**트레이드오프:**
- **장점**: zero-idle 달성, 자동 스케일링, 운영 오버헤드 제거
- **단점 1 (신규 리스크)**: **콜드 스타트** — Lambda Container 1.35s [Case: openclaw]. p99 <100ms SLA 요구 시 부적합. Provisioned Concurrency 또는 SnapStart로 완화 [AWS Docs — Lambda SnapStart]
- **단점 2**: 동기 페이로드 **6MB** 한계 — 대용량 응답은 스트리밍(200MB) 또는 S3 presigned URL로 우회 [tradeoffs-compute.md §1.1]
- **단점 3**: 동시성 1,000 기본 쿼터 vs API Gateway 10,000 RPS 기본값 불일치 — 부하 테스트 전에 증액 요청 [tradeoffs-compute.md §1.2]
- **단점 4**: 로컬 상태 의존 코드는 stateless 전환 필요 — 세션·일시 파일은 DynamoDB/S3로 [Insight #O4]

**완화책 (콜드 스타트):**
- **EventBridge scheduled pre-warming**: openclaw는 활성 시간대 cron으로 컨테이너 주기 호출하여 first-response 콜드 스타트 제거, 월 ~$0.07 추가 [Case: openclaw] [Insight #O3]
- **SnapStart** (Java 11+, Python 3.12+, .NET 8+): Java는 무료, Python/.NET은 캐시 비용 발생 (최소 3시간분) [AWS Docs — Lambda SnapStart]
- **Provisioned Concurrency**: 엄격한 p99 SLA 필요 시 — 상시 과금이지만 사실상 콜드 스타트 제거

**비용 범위** (예시, 검증 사례 출처 필수):
- openclaw 전체 월 비용 **$1-2/월** (Free Tier 시 $0.23) [Case: openclaw] [Insight #O5]
- ALB 고정비 제거 효과: **$18-25/월** 절감 [Case: openclaw] [Insight #O2]
- Pre-warming 추가 비용: 월 **~$0.07** [Case: openclaw] [Insight #O3]

**이행 체크리스트 스켈레톤:**
- [ ] **Stage 0 (사전 준비)**:
  - [ ] 요청·응답 페이로드 크기 분포 측정 (6MB 초과 경로 식별)
  - [ ] Lambda 동시성 쿼터 증액 요청 (필요 시)
  - [ ] 로컬 상태 의존 지점 스캔 → DynamoDB/S3 외부화 설계
  - [ ] 인증·CORS·API key 정책 API Gateway에 매핑
- [ ] **Stage 1 (저위험 검증)**:
  - [ ] 단일 저빈도 엔드포인트를 Lambda로 이전
  - [ ] 콜드 스타트 p50·p99 측정, SLA 비교
  - [ ] RDS 직접 연결이면 RDS Proxy로 대체
- [ ] **Stage 2 (파일럿)**:
  - [ ] API Gateway weighted routing 또는 Route 53 가중치로 트래픽 X% 분기
  - [ ] CloudWatch 대시보드 (콜드 스타트 빈도, p95/p99, 에러율)
  - [ ] EventBridge pre-warming 적용 후 first-response 개선 측정
- [ ] **Stage 3 (전환)**:
  - [ ] 100% 전환, ALB + EC2 지연 종료 (롤백 윈도우 확보)
  - [ ] 비용 비교 리포트 (ALB 제거 효과 정량화)

**위임(Delegation):** 없음 — 전용 `lambda-deployment` 스킬 미존재. 구현 단계는 [AWS Docs — API Gateway + Lambda](https://docs.aws.amazon.com/apigateway/latest/developerguide/getting-started-with-lambda-integration.html) 참고.

**Citations:**
- [AWS Docs — Lambda quotas](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html)
- [AWS Docs — API Gateway + Lambda](https://docs.aws.amazon.com/apigateway/latest/developerguide/getting-started-with-lambda-integration.html)
- [AWS Docs — Lambda SnapStart](https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html)
- [Insight #O2] — API Gateway로 ALB 고정비 제거
- [Insight #O3] — EventBridge pre-warming
- [Insight #O4] — DynamoDB + S3 session persistence
- [Insight #O5] — Free-tier first cost target
- [tradeoffs-compute.md §1] — Lambda 트레이드오프
- [tradeoffs-data-layer.md §1] — RDS Proxy

---

### Pattern 2.2: ECS 상시 서비스 → Fargate + Fargate Spot 혼합

**적용 조건** (when to use):
- 상시 실행 필요한 컨테이너 서비스 (Lambda 15분 상한 초과 또는 장기 연결)
- 인터럽트 **허용 가능** (재시도·stateless 설계)
- 트래픽이 지속적이나 일부 용량은 중단 내성이 있는 워크로드
- 서비스 단위 운영 (`desiredCount ≥ 2`)

**AS-IS:**
```text
[ALB / API Gateway]
   |
   v
[ECS Service (FARGATE 전부)]
  ├─ Task A (FARGATE) ─┐
  ├─ Task B (FARGATE) ─┼─▶ 모두 On-Demand 과금
  └─ Task C (FARGATE) ─┘

  평균 CPU 30% → 70% idle 비용
```

**TO-BE:**
```text
[ALB / API Gateway]
   |
   v
[ECS Service (capacityProviderStrategy 혼합)]
  ├─ FARGATE weight=1        ─▶ Task 1 (기준 용량)
  └─ FARGATE_SPOT weight=4   ─▶ Task 2-5 (Spot, 70% 절감)
       │
       └─ SIGTERM 핸들러 + 2분 drain + 외부 상태

  서비스 레벨 desiredCount ≥ 2
```

**핵심 변경:**
- `capacityProviderStrategy`로 On-Demand와 Spot 혼합 [AWS Docs — Fargate capacity providers]
- 대부분 용량을 Spot으로 전환 (~70% 컴퓨트 절감) [Case: openclaw] [Insight #O1]
- 단일 태스크 Spot 운영 금지 — 서비스 + `desiredCount ≥ 2`가 최소 조건 [tradeoffs-compute.md §3.1]
- SIGTERM 핸들러로 2분 내 graceful drain 구현 [tradeoffs-compute.md §3.2]

**트레이드오프:**
- **장점**: 70% 컴퓨트 절감 [Insight #O1], 기존 컨테이너 이미지 그대로 재사용
- **단점 1**: **자동 On-Demand fallback 없음** — 용량 부족 시 시작 지연만 발생 [AWS Docs]. `FARGATE` weight로 기준 용량 확보 필수
- **단점 2 (안티패턴)**: 단일 태스크에 Fargate Spot 적용 시 용량 확보까지 완전 중단 — 가용성 위험 [tradeoffs-compute.md §3]
- **단점 3**: SIGTERM 핸들러 의무 — 2분 내 정리 실패 시 데이터 손상 [AWS Docs]
- **단점 4**: 상태 저장 불가 — in-memory 세션·임시 파일 의존 코드 stateless화 필요

**openclaw의 설계 패턴 (dual-compute):**
- **Primary**: Lambda Container (zero-idle, 1.35s cold start)
- **Fallback**: ECS Fargate Spot (15분 초과 · 고부하 요청, ~70% 절감) [Case: openclaw] [Insight #O1]
- 본 패턴은 ECS 기존 서비스를 직접 Fargate Spot 혼합으로 전환할 때 사용. openclaw dual-compute는 Lambda primary 구성을 전제로 하므로 Pattern 2.1과 결합 가능.

**비용 범위** (예시, 검증 사례 출처 필수):
- Fargate Spot 컴퓨트 절감: **~70%** (On-Demand 대비) [Case: openclaw] [Insight #O1]
- openclaw 전체 월 비용은 $1-2 (Lambda primary + Fargate Spot fallback 조합) [Insight #O5]

**이행 체크리스트 스켈레톤:**
- [ ] **Stage 0 (사전 준비)**:
  - [ ] 태스크 stateless 검증 (in-memory 세션·로컬 파일 의존 제거)
  - [ ] SIGTERM 핸들러 구현 (2분 내 drain + 외부 상태 flush)
  - [ ] `stopTimeout` 설정 (기본 30초, 최대 120초)
  - [ ] `desiredCount ≥ 2` 확인
- [ ] **Stage 1 (저위험 검증)**:
  - [ ] 비프로덕션 클러스터에 `FARGATE_SPOT` weight 도입
  - [ ] AWS FIS 또는 수동 task 종료로 SIGTERM 경로 검증
  - [ ] EventBridge `ECS Task State Change` + `stopCode: "SpotInterruption"` 알람 연결 [tradeoffs-spot.md §6.2]
- [ ] **Stage 2 (파일럿)**:
  - [ ] 프로덕션에 `FARGATE` weight=1 + `FARGATE_SPOT` weight=4 적용
  - [ ] 인터럽트 발생 시 스케줄러 자동 재생성 확인
  - [ ] 비용·인터럽트률 대시보드 (Spot reclaim 빈도)
- [ ] **Stage 3 (전환)**:
  - [ ] weight 비율 최적화 (예: Spot weight=7로 확대)
  - [ ] 장기 관측 후 `FARGATE` baseline 재조정

**위임(Delegation):** 없음 — 전용 `fargate-service` 스킬 미존재. 구현 단계는 [AWS Docs — Fargate capacity providers](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-capacity-providers.html) 참고.

**Citations:**
- [AWS Docs — Fargate capacity providers](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-capacity-providers.html)
- [AWS Docs — ECS Task State Change events](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs_cwe_events.html)
- [Insight #O1] — Lambda + Fargate Spot dual-compute
- [Insight #O5] — Free-tier cost target
- [tradeoffs-compute.md §3] — Fargate 트레이드오프
- [tradeoffs-spot.md §5, §6] — Spot Do/Don't 및 인터럽트 추적

---

### Pattern 2.3: WebSocket 상시 → API Gateway WebSocket + Lambda

**적용 조건** (when to use):
- 양방향 메시지 기반 실시간 통신 (채팅, 알림, 협업)
- 개별 메시지 처리가 짧음 (<15분) — **연결 수명 != 함수 수명**
- 연결 상태는 외부에 저장 가능 (DynamoDB / ElastiCache)
- 순수 streaming(비디오·gRPC streaming)은 아니고 이벤트 기반 메시지

**AS-IS:**
```text
[Client] ◀── WebSocket long-lived ──▶ [EC2 상시 (Node.js ws server)]
                                         ├─ in-memory connection map
                                         ├─ room state (local)
                                         └─ broadcast via memory

  연결 수 × 서버 리소스 = 상시 비용
```

**TO-BE:**
```text
[Client]
   |
   └── wss://...execute-api... ──▶ [API Gateway WebSocket API]
                                     │
                                     ├─ $connect ─▶ [Lambda] ─▶ [DynamoDB: connectionId ↔ userId]
                                     ├─ $default ─▶ [Lambda] ─▶ 메시지 라우팅
                                     └─ $disconnect ─▶ [Lambda] ─▶ DynamoDB cleanup

  메시지 단위 과금 + 연결 시간(분당) 과금
```

**핵심 변경:**
- EC2 상시 WebSocket 서버 제거 → API Gateway WebSocket API
- 연결 상태(connectionId ↔ userId / room) DynamoDB로 외부화
- 각 메시지는 독립 Lambda 호출로 처리 (stateless)
- Broadcast는 `PostToConnection` API로 DynamoDB 조회 후 전송

**트레이드오프:**
- **장점**: 서버 운영 제거, 연결 수에 자동 확장, 메시지 단위 정확한 과금
- **단점 1**: **연결 상태 외부화 필수** — DynamoDB/ElastiCache 왕복 오버헤드
- **단점 2**: **Lambda 실행 시간 15분 상한** — 연결 수명 ≠ 함수 수명. long-running 로직 재설계 필요 [AWS Docs — Lambda quotas]
- **단점 3**: Broadcast 팬아웃 시 DynamoDB 스캔·GSI 설계 필요 — 연결 수 증가 시 지연·비용 상승
- **단점 4**: API Gateway WebSocket 과금은 **연결 시간(분) + 메시지 개수** 두 축 — 매우 많은 유휴 연결이 상시 있으면 오히려 비쌀 수 있음 [AWS Docs — API Gateway pricing]
- **단점 5**: 진짜 streaming(비디오)·gRPC streaming 워크로드는 Fargate 유지 권고 [tradeoffs-compute.md §1.3]

**비용 범위** (예시, 검증 사례 출처 필수):
- openclaw는 메시지 기반 상태 UI 구성에 WebSocket 대신 **EventBridge scheduled pre-warming**으로 first-response를 제거함 [Case: openclaw] [Insight #O3]. 본 패턴의 WebSocket 특화 벤치마크는 검증 사례에 직접 없음 — AWS Docs 공식 과금 모델만 참조.

**이행 체크리스트 스켈레톤:**
- [ ] **Stage 0 (사전 준비)**:
  - [ ] 연결·메시지·방(room) 모델을 DynamoDB 테이블 설계로 변환
  - [ ] GSI 설계 (예: `userId` → `connectionId` 역조회)
  - [ ] 기존 in-memory 상태 의존 로직 인벤토리
  - [ ] TTL 설정으로 stale 연결 자동 정리
- [ ] **Stage 1 (저위험 검증)**:
  - [ ] 단일 채팅방 프로토타입 ($connect/$default/$disconnect)
  - [ ] Broadcast 팬아웃 성능 측정 (연결 수 × 메시지 빈도)
  - [ ] 연결 시간 과금 단가 계산 (`$0.25/million minutes` 기준)
- [ ] **Stage 2 (파일럿)**:
  - [ ] 트래픽 일부 WebSocket API로 분기
  - [ ] 롤백 플랜: Route 53 가중치 / 클라이언트 feature flag
  - [ ] 이상 연결 탐지·자동 종료 로직
- [ ] **Stage 3 (전환)**:
  - [ ] 전체 전환, EC2 WebSocket 서버 종료
  - [ ] 동시 연결 수 · 메시지 TPS · DynamoDB 비용 대시보드

**위임(Delegation):** 없음 — 전용 스킬 미존재. 구현 단계는 [AWS Docs — API Gateway WebSocket](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api.html) 참고.

**Citations:**
- [AWS Docs — API Gateway WebSocket](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api.html)
- [AWS Docs — Lambda quotas](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html)
- [Insight #O3] — openclaw의 pre-warming 대체 접근
- [tradeoffs-compute.md §1] — Lambda 15분 상한 · streaming 부적합

---

### Pattern 2.4: Java monolith on EC2 → Lambda + SnapStart

**적용 조건** (when to use):
- Java 11+ / Python 3.12+ / .NET 8+ 런타임 [AWS Docs — Lambda SnapStart]
- 클래스로딩 · Spring Boot 초기화 · JVM warmup 비용이 큰 앱
- 요청 처리 자체는 <15분
- 컨테이너 이미지가 아닌 **zip 배포** (SnapStart는 컨테이너 이미지 미지원)
- Provisioned Concurrency의 상시 과금을 피하고 싶은 경우

**AS-IS:**
```text
[ALB]
  |
  v
[EC2 (Tomcat + Spring Boot, 상시)]
  ├─ 부팅 시 클래스로딩 30-60s
  ├─ JIT warmup 수 분
  └─ 상시 메모리 점유

  ALB + EC2 idle 비용 (Pattern 2.1과 공통)
```

**TO-BE:**
```text
[API Gateway]
  |
  v
[Lambda (Java + SnapStart 활성화)]
  ├─ 게시된 version 또는 alias
  ├─ beforeCheckpoint / afterRestore 훅 구현
  └─ sub-second 복원 지연

  zero-idle + 콜드 스타트 완화
```

**핵심 변경:**
- EC2 상시 + ALB → API Gateway + Lambda (Pattern 2.1 기반)
- **SnapStart 활성화** — published version 또는 alias 단위 [AWS Docs]
- `$LATEST` unqualified 호출은 SnapStart 미적용 — alias/version 강제 사용
- Provisioned Concurrency와 SnapStart는 **상호배타** — 하나만 선택 [AWS Docs]

**트레이드오프:**
- **장점 1**: 콜드 스타트 sub-second 수준 (Spring Boot 전통적 30-60s 대비 극적 개선)
- **장점 2 (Java)**: 요청·실행시간·메모리만 과금 — **추가 비용 없음** [AWS Docs — Lambda SnapStart]
- **단점 1 (Python/.NET)**: 캐시 + 복원 비용 추가 (메모리 기반, 리전 단가), 최소 **3시간분** 과금 [AWS Docs]. 호출 빈도가 매우 낮으면 오히려 Provisioned Concurrency가 나을 수 있음
- **단점 2**: **VPC ENI 재연결 지연** — VPC 안에서 RDS/Redis 초기화하는 함수는 SnapStart 효과 제한적 [AWS Docs]. ENI 연결이 병목.
- **단점 3 (Uniqueness 함정)**: 스냅샷 시점의 난수·UUID·TLS 세션 키가 모든 복원 인스턴스에 복제됨 — 금융·인증 계열에서는 fresh entropy 재생성 훅 필수 [AWS Docs]
- **단점 4**: 컨테이너 이미지 미지원 — zip 배포로 전환 필요. 250MB (unzipped, layer 포함) 한계 [tradeoffs-compute.md §1.1]
- **단점 5**: Java 14일 미호출 시 Inactive → 다음 호출 시 재초기화 (`SnapStartNotReadyException`) [AWS Docs]
- **단점 6**: Provisioned Concurrency · EFS · 512MB 초과 ephemeral storage와 **상호배타** [AWS Docs]

**Uniqueness 완화 패턴:**
- 난수·UUID·TLS 세션 키는 **핸들러 내부**에서 생성 (초기화 단계가 아니라)
- `afterRestore` 훅에서 DB/Redis 커넥션 재확립, JWT 키 회전
- AWS SDK 자격증명은 `AWS_CONTAINER_CREDENTIALS_FULL_URI`로 자동 갱신됨 [AWS Docs]

**비용 범위** (예시, 검증 사례 출처 필수):
- openclaw는 Lambda Container를 사용하므로 **SnapStart 미적용** (컨테이너 이미지 제외 조건) — 본 패턴의 Java+SnapStart 직접 벤치마크는 검증 사례에 없음.
- 참조 상수: openclaw Lambda Container 콜드 스타트 **1.35s**, warm 0.12s [Case: openclaw]. SnapStart는 sub-second 공언 [AWS Docs]로 이보다 낮은 지연 기대.
- Java SnapStart는 추가 비용 없음 [AWS Docs] — Pattern 2.1 비용 범위와 동일 가정 가능.

**이행 체크리스트 스켈레톤:**
- [ ] **Stage 0 (사전 준비)**:
  - [ ] zip 배포 전환 (컨테이너 이미지 사용 중이면)
  - [ ] Java 11+ / Python 3.12+ / .NET 8+ 확인
  - [ ] Uniqueness 재검토 — 초기화 단계의 난수·TLS 키 생성 지점 스캔
  - [ ] `beforeCheckpoint` / `afterRestore` 훅 구현 (Java CRaC API)
- [ ] **Stage 1 (저위험 검증)**:
  - [ ] alias + published version으로 SnapStart 활성화
  - [ ] 콜드 스타트 p50·p99 측정 (활성 전후 비교)
  - [ ] DB 커넥션 재확립 경로 검증
- [ ] **Stage 2 (파일럿)**:
  - [ ] 트래픽 X% alias로 분기, 14일 inactive 조건 확인
  - [ ] Uniqueness 취약 지점 (세션 키 중복) 감사
  - [ ] Python/.NET일 경우 캐시 비용 관찰 (최소 3시간 과금)
- [ ] **Stage 3 (전환)**:
  - [ ] EC2 Tomcat 제거, alias 100% 트래픽
  - [ ] 릴리스마다 alias shift 워크플로 확립

**위임(Delegation):** 없음 — 전용 스킬 미존재. 구현 단계는 [AWS Docs — Lambda SnapStart](https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html) 참고.

**Citations:**
- [AWS Docs — Lambda SnapStart](https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html)
- [AWS Docs — Lambda quotas](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html)
- [tradeoffs-compute.md §1] — Lambda 콜드 스타트 완화 수단
- [Case: openclaw] — Lambda Container 1.35s cold start 참조 상수

---

## 3. Anti-patterns

**A1. 콜드 스타트 p99 <100ms 요구하면서 Lambda 선택**
- Lambda Container 1.35s, SnapStart 최적 sub-second — p99 <100ms는 Provisioned Concurrency + warm-up 없이는 불가능 [AWS Docs — Lambda]
- 해당 SLA는 Fargate 상시 유지 또는 EC2로 회귀하는 것이 맞음

**A2. Fargate Spot 단일 태스크로 운영**
- `desiredCount = 1` + Fargate Spot = 인터럽트 시 용량 확보까지 완전 중단 [tradeoffs-compute.md §3]
- 반드시 서비스 + `desiredCount ≥ 2` 또는 `FARGATE` capacity provider weight로 기준 용량 확보

**A3. 6MB 초과 응답을 Lambda 동기 호출로 반환**
- 동기 요청·응답 각 6MB 한계 [tradeoffs-compute.md §1.1]
- 대용량은 스트리밍(200MB) 또는 S3 presigned URL로 우회

**A4. SnapStart와 Provisioned Concurrency 동시 활성화 시도**
- 상호배타 — 둘 중 하나만 선택 가능 [AWS Docs — Lambda SnapStart]
- 엄격 p99 SLA는 Provisioned Concurrency, 비용 우선은 SnapStart

**A5. 로컬 상태 의존 코드의 직접 Lambda 이식**
- in-memory session, 로컬 파일, 프로세스 내부 캐시 의존 로직은 "share nothing" 원칙 위배 (Serverless Lens 원칙 3)
- DynamoDB + S3로 외부화 필요 [Insight #O4]

**A6. WebSocket 대신 Lambda long-polling**
- Lambda 15분 상한 · streaming 대역폭 제한(처음 6MB 무제한 이후 2 MB/s) 때문에 long-polling 부적합 [tradeoffs-compute.md §1.1]
- 양방향 실시간 통신은 API Gateway WebSocket (Pattern 2.3) 또는 Fargate 상시 유지

**A7. SnapStart 초기화 단계에서 난수/세션 키 생성**
- 모든 복원 인스턴스에 복제되는 uniqueness 함정 [AWS Docs]
- 핸들러 내부 또는 `afterRestore` 훅에서 생성해야 함

---

## 4. Citations

- [AWS Docs — Lambda quotas](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html)
- [AWS Docs — API Gateway + Lambda](https://docs.aws.amazon.com/apigateway/latest/developerguide/getting-started-with-lambda-integration.html)
- [AWS Docs — API Gateway WebSocket](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api.html)
- [AWS Docs — ECS Fargate capacity providers](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-capacity-providers.html)
- [AWS Docs — Lambda SnapStart](https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html)
- [AWS Docs — ECS Task State Change events](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs_cwe_events.html)
- [Case: openclaw] — Lambda Container 1.35s, ALB $18-25/월 제거, ~$1/월 운영
- [Insight #O1] — Lambda + Fargate Spot dual-compute
- [Insight #O2] — API Gateway over ALB
- [Insight #O3] — EventBridge scheduled pre-warming
- [Insight #O4] — DynamoDB + S3 session persistence
- [Insight #O5] — Free-tier first cost target
- [Insight #O6] — CloudFront + S3 for web UI (참고; 정적 UI는 별도 패턴)
- Cross-refs: [tradeoffs-compute.md §1, §3], [tradeoffs-data-layer.md §1, §2], [tradeoffs-spot.md §5, §6]
