> **Snapshot date**: 2026-04-18
> **Tier**: 3 (데이터 레이어 이행) — **검증 사례 없음**
> **Description**: RDS→DynamoDB, CDC 전이

# Tier 3 Migration Patterns — Data Layer

> ⚠️ **Tier 3 검증 경고**
>
> 본 스킬이 참조하는 두 검증 사례(serverless-autoresearch, serverless-openclaw)는 Tier 3 데이터 이행을 직접 검증하지 않았습니다. 본 문서는 AWS 공식문서 기반 원칙·체크리스트·AWS Docs 링크만 제공합니다.
>
> 데이터 이행은 **Tier 1/2 중에서도 가장 고위험** 영역이며, 특히 **엔진 간 이전(RDS → DynamoDB)**은 모델 재설계·롤백 비용이 크므로 다음을 **필수**로 합니다:
> 1. 소규모 access pattern으로 파일럿 검증
> 2. CDC 기반 dual-write + read-diff 모니터링
> 3. 롤백 플랜 사전 리허설
>
> 참고: SPEC §9 "Tier 3 취급 방침", [patterns-tier3-monolith.md](patterns-tier3-monolith.md) §Warning.

## 1. Scope of this document

**포함**:
- 검증 가능한 공식 한계 기반의 **이전 리스크 단계별 분류**
- Aurora Serverless v2 / DynamoDB / S3 Express 이전의 원칙 수준 체크리스트
- 공통 패턴: CDC 기반 dual-write, read-diff 모니터링, 단계적 절체

**미포함**:
- 조직별 구체 ETL 스크립트
- 데이터 모델 자동 변환 (관계형 → NoSQL 재설계는 도메인 전문가 영역)
- 비용·기간 추정 (검증 데이터 없음)

세부 AWS Docs 수치·한계는 [tradeoffs-data-layer.md](tradeoffs-data-layer.md)로 위임.

## 2. Patterns

### Pattern 4.1: RDS → Aurora Serverless v2 (동일 엔진 유지)

**적용 조건** (when to use):
- 동일 엔진 — MySQL↔MySQL / PostgreSQL↔PostgreSQL [tradeoffs-data-layer.md §1]
- 기존 애플리케이션 SQL·DDL 그대로 승계 가능
- idle 구간이 뚜렷하거나 트래픽이 spiky (ACU 스케일 이득)
- 커넥션 폭주 대비 RDS Proxy 도입 가능

**리스크 수준**: **낮음** — 엔진 호환이라 데이터 모델 재설계 불요

**AS-IS:**
```text
[App on EC2/Lambda]
   |
   v
[RDS db.m5.large 상시]
  ├─ idle 8h/day (예: 야간)
  └─ 고정 인스턴스 과금

  peak 대응 위해 over-provisioning
```

**TO-BE:**
```text
[App on Lambda]
   |
   v
[RDS Proxy] ─▶ [Aurora Serverless v2 cluster (ACU 0.5-16)]
                  ├─ 0.5 ACU 단위 초 단위 스케일
                  ├─ min ACU 선택: 0 (auto-pause) or >0 (항상 warm)
                  └─ Multi-AZ · Global DB 지원

  burst 시 순식간 확장, idle 시 min까지 축소
```

**핵심 변경:**
- 고정 인스턴스 → ACU 기반 서버리스 컴퓨트 [AWS Docs — Aurora Serverless v2]
- 0.5 ACU 단위의 초 단위 연속 스케일 — v1 대비 개선 [tradeoffs-data-layer.md §1.2]
- RDS Proxy 도입으로 Lambda ↔ Aurora 커넥션 풀링 최적화
- 동일 클러스터 내 Provisioned + Serverless v2 혼합 가능 (점진 전환 경로)

**트레이드오프:**
- **장점**: 동일 엔진 유지로 애플리케이션 변경 최소, 자동 스케일, downtime 없는 온라인 스케일
- **단점 1 (바닥 비용 함정)**: `min ACU > 0` 설정 시 idle 시에도 항상 과금 [tradeoffs-data-layer.md §1.2]. 완전 zero-idle 원할 경우 min=0 + auto-pause — 단 resume 지연 수용
- **단점 2**: `min=0` 자동 pause → resume 시 수 초 지연 — 사용자 대면 API의 first-request에 영향
- **단점 3**: Database Activity Streams, Cluster Cache Management(Aurora PG), Aurora Auto Scaling 미지원 [AWS Docs]
- **단점 4**: writer + reader 각 인스턴스별 min ACU 과금 — 2개 인스턴스 × min=1이면 항상 최소 2 ACU 청구

**이행 체크리스트:**
- [ ] **Stage 0 (사전 준비)**:
  - [ ] 기존 RDS 스냅샷 + 테스트 환경 복원
  - [ ] 애플리케이션 커넥션 풀링 전략 재검토 (Lambda 동시성 대비 RDS Proxy 필요성)
  - [ ] ACU 범위 산정 (peak QPS · 메모리 요구 기반)
  - [ ] min ACU 결정 (0 vs >0) — SLA와 비용 균형
- [ ] **Stage 1 (저위험 검증)**:
  - [ ] 동일 클러스터에 Serverless v2 인스턴스 추가 (Provisioned 유지)
  - [ ] 부하 테스트로 ACU 스케일 동작 확인
  - [ ] RDS Proxy 엔드포인트로 Lambda 동시 커넥션 테스트
- [ ] **Stage 2 (파일럿)**:
  - [ ] reader 일부를 Serverless v2로 전환, read 트래픽 검증
  - [ ] failover 리허설 (Multi-AZ)
  - [ ] 비용·스케일 로그 관찰
- [ ] **Stage 3 (전환)**:
  - [ ] writer를 Serverless v2로 전환 (엔진 호환이라 DDL 변경 없음)
  - [ ] 이전 Provisioned 인스턴스 일정 기간 유지 (롤백용)
  - [ ] 이전 인스턴스 종료

**위임(Delegation):** 없음 — 전용 스킬 미존재. 구현 단계는 [AWS Docs — Aurora Serverless v2](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2.html) 참고.

**Citations:**
- [AWS Docs — Aurora Serverless v2](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2.html)
- [AWS Docs — RDS Proxy](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.html)
- [tradeoffs-data-layer.md §1] — Aurora Serverless v2 정량 한계 및 함의

---

### Pattern 4.2: RDS → DynamoDB (access pattern 재설계)

**적용 조건** (when to use):
- 주요 access pattern이 **3-5개 이내**로 식별됨 (단일 테이블 설계 가능)
- 관계형 JOIN 의존이 낮거나 제거 가능 (애플리케이션 수준 해결)
- key-value 또는 document-oriented 접근이 주류
- 서버리스 Lambda 동시성 확장과 매칭 필요

**리스크 수준**: **매우 높음** — 쿼리 유연성 상실, 데이터 모델 재설계 필수, 롤백 비용 큼

**AS-IS:**
```text
[App]
   |
   v
[RDS (정규화된 다중 테이블)]
  ├─ users · orders · items · inventories
  ├─ SQL JOIN으로 조합 쿼리
  └─ ad-hoc 쿼리 가능
```

**TO-BE:**
```text
[App]
   |
   v
[DynamoDB (single-table design)]
  ├─ PK: entity_type#id
  ├─ SK: nested entity sort key
  ├─ GSI1 / GSI2: access pattern별 역인덱스
  └─ 사전 식별된 쿼리만 고효율

  ad-hoc 쿼리는 Athena/S3 export로 별도 처리
```

**핵심 변경:**
- **데이터 모델 재설계 필수** — 관계형 JOIN 패턴을 DynamoDB 단일 테이블 설계로 재구성 [AWS Docs — DynamoDB single-table design]
- Access pattern을 **사전에** 나열하고 그것을 전제로 PK/SK/GSI 설계
- 이전 방식: DMS CDC target으로 2-way sync 구간 설정 → dual-write → read diff → cutover

**트레이드오프:**
- **장점**: On-Demand mode 시 zero-idle, Lambda 동시성과 자연 매칭, 무한 스케일
- **단점 1**: **쿼리 유연성 상실** — 사전 설계되지 않은 쿼리는 full scan 또는 별도 분석 스토리지 필요
- **단점 2**: **롤백 비용 매우 높음** — 재동기 비용, 기간 (수 주~수 개월)
- **단점 3**: Strong vs eventual consistency 선택이 비용에 직결 [tradeoffs-data-layer.md §2.2]
- **단점 4**: GSI를 많이 걸면 write 비용 증가 (write 시 모든 GSI 업데이트)
- **단점 5**: 트랜잭션이 TransactWriteItems로 제한됨 (25개 아이템, 4MB) — 복잡한 멀티 엔티티 트랜잭션 재설계 필요
- **단점 6**: On-Demand max throttle 설정 없이 운영 시 **무한 비용 폭주** 위험 — per-table max 설정 필수 [tradeoffs-data-layer.md §2.1]

**이행 체크리스트:**
- [ ] **Stage 0 (사전 준비)**:
  - [ ] **Access pattern 문서화** — key + query shape를 3-5개 이내로 정리 (전체가 10개 초과면 패턴 재고)
  - [ ] Single-table design 스케치 (PK/SK/GSI)
  - [ ] 트랜잭션 경계 재검토 — DynamoDB TransactWriteItems 한계 수용 가능 여부
  - [ ] Athena·S3 export로 ad-hoc 쿼리 대안 마련
  - [ ] per-table max capacity 설정값 결정 (비용 폭주 방지)
- [ ] **Stage 1 (저위험 검증)**:
  - [ ] 파일럿 테이블 (저중요도 엔티티)로 CDC 설정 (DMS source=RDS, target=DynamoDB)
  - [ ] 샘플 애플리케이션 경로로 read/write 이중화 (dual-write)
  - [ ] 모델·쿼리 성능 측정
- [ ] **Stage 2 (파일럿)**:
  - [ ] dual-write + **read-diff 모니터링** — 일정 기간 DynamoDB read 결과를 RDS와 대조
  - [ ] throughput·latency·cost 대시보드
  - [ ] 실패 시나리오 시뮬레이션 — **롤백 리허설 필수**
- [ ] **Stage 3 (전환)**:
  - [ ] read cutover (RDS write 유지, read는 DynamoDB)
  - [ ] write cutover (DynamoDB primary, RDS는 일정 기간 shadow로 유지)
  - [ ] 관측 기간 확보 후 RDS 폐기 (최소 수 주)
  - [ ] 모드 전환 제한(Provisioned → On-Demand 24시간당 최대 4회) 사전 고려

**위임(Delegation):** 없음 — 전용 스킬 미존재. 구현 단계는 [AWS Docs — DMS CDC](https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Task.CDC.html) 및 [AWS Docs — DynamoDB single-table design](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-modeling-nosql-B.html) 참고.

**Citations:**
- [AWS Docs — DMS CDC](https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Task.CDC.html)
- [AWS Docs — DynamoDB Read/Write Capacity Mode](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadWriteCapacityMode.html)
- [AWS Docs — DynamoDB single-table design](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-modeling-nosql-B.html)
- [AWS Docs — DynamoDB TransactWriteItems](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html)
- [tradeoffs-data-layer.md §2] — DynamoDB 트레이드오프

---

### Pattern 4.3: Batch 읽기 가속 — S3 Express One Zone 캐시 도입

**적용 조건** (when to use):
- 고빈도 object GET — 요청 단가가 비용 지배적인 워크로드
- 훈련 데이터 shuffle, 분석 중간 결과, 인터랙티브 크리에이티브 워크로드
- EC2/Fargate/Lambda와 **동일 AZ**에 배치 가능
- 장기 아카이브·다중 리전 재해복구 요구 없음

**리스크 수준**: **중간** — 단일 AZ 제약과 비용 역전 함정

**AS-IS:**
```text
[Training job on EC2/Fargate (ml AZ: us-east-1a)]
   |
   v
[S3 Standard (리전 복수 AZ)]
  ├─ shuffle/read 고빈도
  ├─ 요청 단가 지배적
  └─ 수십 ms 지연
```

**TO-BE:**
```text
[Training job (동일 AZ us-east-1a)]
   |
   v
[S3 Express One Zone directory bucket (us-east-1a)]
  ├─ 요청 단가 ~50% 절감
  ├─ 한 자리 ms 지연 (~10× 저지연)
  ├─ 중간 결과만 저장
  └─ 원본은 S3 Standard에 별도 보관

  쓰기 경로는 S3 Standard 유지 가능 (원본 내구성)
```

**핵심 변경:**
- 읽기 workload만 S3 Express로 라우팅; 쓰기 경로는 S3 Standard 유지 옵션
- 버킷 네이밍 규칙: `{base}--{zone-id}--x-s3` 필수 [AWS Docs — S3 Express One Zone]
- Directory bucket 스키마 — 계층형 디렉토리, flat prefix와 다름 [tradeoffs-data-layer.md §3.1]
- `s3express:CreateSession` 인증 모델 — SDK·IAM 정책 업그레이드 필요

**트레이드오프:**
- **장점**: 요청 단가 ~50% 저렴, 한 자리 ms 지연, 동일 AZ DTO 비용 0 [tradeoffs-data-layer.md §3.1]
- **단점 1 (단일 AZ 가용성)**: AZ 장애 시 데이터 유실 가능 — 원본은 Standard/Glacier에 **반드시** 별도 보관 [tradeoffs-data-layer.md §3.2]
- **단점 2 (비용 역전 함정)**: 저빈도 접근 시 Standard 대비 **총비용 증가** — 요청 단가 절감은 요청 빈도에 비례 [AWS Docs]
- **단점 3 (기능 제한)**: 버저닝 없음, CRR/SRR 없음, Lifecycle 제한, Intelligent-Tiering·Glacier 불가 [AWS Docs]
- **단점 4 (암호화 제한)**: SSE-C 미지원; SSE-S3/SSE-KMS만 [AWS Docs]
- **단점 5 (CDN 오리진 부적합)**: Block Public Access 항상 On, ACL 비활성 → 공개 CDN 오리진으로 부적합 [AWS Docs]

**이행 체크리스트:**
- [ ] **Stage 0 (사전 준비)**:
  - [ ] 워크로드의 AZ 고정 가능성 확인 (EC2/Fargate launch 전략)
  - [ ] 요청 빈도 측정 — 빈도가 낮으면 비용 역전 위험, Express 도입 재고
  - [ ] 원본 S3 Standard 유지 경로 설계 (내구성·규제 대응)
  - [ ] SDK 최신 버전 + IAM 정책 업그레이드 (CreateSession 권한)
- [ ] **Stage 1 (저위험 검증)**:
  - [ ] 파일럿 directory bucket 생성 (`{base}--{zone-id}--x-s3` 네이밍)
  - [ ] 샘플 훈련 잡의 shuffle 경로를 Express로 전환
  - [ ] 지연·비용·요청 성공률 측정
- [ ] **Stage 2 (파일럿)**:
  - [ ] 프로덕션 워크로드 일부 이전
  - [ ] AZ 장애 시나리오 시뮬레이션 (해당 AZ 차단 → 원본 Standard fallback 검증)
  - [ ] 쿼터(리전별 디렉토리 버킷 100개) 증설 필요성 모니터링
- [ ] **Stage 3 (전환)**:
  - [ ] 읽기 경로 100% Express 전환
  - [ ] 쓰기 경로는 선택적: 원본 내구성 중요 시 Standard 유지
  - [ ] 기존 캐시 인프라 (ElastiCache 등) 축소 가능성 재평가

**위임(Delegation):** 없음 — 전용 스킬 미존재. 구현 단계는 [AWS Docs — S3 Express One Zone](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-express-one-zone.html) 참고.

**Citations:**
- [AWS Docs — S3 Express One Zone](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-express-one-zone.html)
- [AWS Docs — Directory buckets overview](https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-overview.html)
- [tradeoffs-data-layer.md §3] — S3 Standard vs Express 비교

---

## 3. Do / Don't

| Do | Don't |
|----|-------|
| 단일 access pattern으로 파일럿 시작 | 전체 테이블 한 번에 이전 시도 |
| CDC(DMS) 기반 점진 이전 | blue/green 한 번 컷오버 |
| read-diff 모니터링으로 이행 정확성 검증 | 쓰기만 검증 후 바로 read cutover |
| per-table max 설정 (DynamoDB On-Demand) | max 없이 운영 (비용 폭주 위험) |
| Aurora Serverless v2에 RDS Proxy 결합 | Lambda가 직접 Aurora에 커넥션 다수 생성 |
| S3 Express 도입 시 **동일 AZ** 배치 | 다중 AZ 워크로드에 Express 사용 (DTO·지연 이득 상실) |
| 원본은 Standard/Glacier에 유지 | 중요 데이터의 **유일 복사본**을 Express에 저장 |
| 롤백 플랜 사전 리허설 | 이행 후 문제 발생 시 즉흥 대응 |
| access pattern 문서화 선행 | 기존 SQL을 그대로 NoSQL로 옮기려 시도 |
| Strong vs eventual 일관성 비용 명시 | 기본값(Strong)만 사용 (RRU 2배 과금) |

## 4. 의사결정 질문 (Phase 3 인터뷰 보조)

- **Q**: 엔진 변경 허용 가능?
  - No (MySQL/PostgreSQL 유지) → **Pattern 4.1** (Aurora Serverless v2) 경로
  - Yes → Pattern 4.2 검토 대상

- **Q**: Access pattern 수?
  - ≤5 → Pattern 4.2 (DynamoDB 재설계) 가능
  - 6-10 → 파일럿 권장, 단일 테이블 설계 난이도 상승
  - >10 → **Pattern 4.2 부적합** — Aurora Serverless v2 또는 하이브리드

- **Q**: ad-hoc 분석 쿼리 빈도?
  - 낮음 → DynamoDB 수용 가능 (S3 export + Athena)
  - 높음 → Aurora Serverless v2 유지 + DynamoDB 공존 (hot path만 분리)

- **Q**: 읽기 빈도 vs 스토리지 규모?
  - 고빈도 읽기 (> 1M GET/day) → **Pattern 4.3** (S3 Express) 검토
  - 저빈도 접근 → Standard 유지 (비용 역전 회피)

- **Q**: AZ 고정 가능?
  - Yes → S3 Express 도입 가능
  - No (multi-AZ 워크로드) → S3 Express 부적합

## 5. Citations

- [AWS Docs — Aurora Serverless v2](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2.html)
- [AWS Docs — RDS Proxy](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.html)
- [AWS Docs — DMS CDC](https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Task.CDC.html)
- [AWS Docs — DynamoDB Read/Write Capacity Mode](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadWriteCapacityMode.html)
- [AWS Docs — DynamoDB single-table design](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-modeling-nosql-B.html)
- [AWS Docs — DynamoDB TransactWriteItems](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html)
- [AWS Docs — S3 Express One Zone](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-express-one-zone.html)
- [AWS Docs — Directory buckets overview](https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-overview.html)
- [AWS prescriptive guidance — Strangler Fig in data persistence](https://docs.aws.amazon.com/prescriptive-guidance/latest/modernization-data-persistence/strangler-fig.html)
- Cross-refs: [tradeoffs-data-layer.md §1~3](tradeoffs-data-layer.md), [patterns-tier3-monolith.md](patterns-tier3-monolith.md)

---

*본 문서는 Tier 3 데이터 이행 시 **원칙·리스크·체크리스트 skeleton**에 한정. 실제 이행은 조직별 파일럿과 도메인 전문가 설계를 전제로 한다.*
