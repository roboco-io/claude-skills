> **Snapshot date**: 2026-04-18
> **Description**: RDS / Aurora Serverless v2 / DynamoDB / S3 Express

# Data Layer Tradeoffs

Tier 3 이행에서 가장 까다로운 의사결정. 실 검증 사례가 부족한 영역이므로 **AWS Docs 기반 원칙 + 공식 한계 + 리스크 경고**로 구성. 구체적인 이행 단계 패턴은 Stage D에서 작성될 [patterns-tier3-data.md](patterns-tier3-data.md)로 위임.

## 1. RDS → Aurora Serverless v2

Primary citation: [AWS Docs — Aurora Serverless v2](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2.html)

### 1.1 정량 한계

| 항목 | 값 | 출처 |
|------|-----|------|
| ACU 정의 | 1 ACU ≈ 2 GiB RAM + 상응 CPU·네트워킹 | [AWS Docs] |
| ACU 증분 | **0.5 ACU** 단위, 초 단위 연속 측정 | [AWS Docs] |
| ACU 범위 | 엔진·버전별 `0.5-128` → `0.5-256` → **`0-256`** (Aurora MySQL 3.08.0+ / PostgreSQL 13.15+, 14.12+, 15.7+, 16.3+) | [AWS Docs] |
| 스케일 반응성 | 수 초 이내 온라인 스케일 (downtime 없음) | [AWS Docs] |
| Auto-pause | min=0 설정 시 idle 후 자동 pause → 새 커넥션에 즉시 resume | [AWS Docs] |
| v2 콜드 스타트 | v1 대비 **제거** (지속 실행 인스턴스) — 단 pause→resume 시 수 초 지연 | [AWS Docs] |
| Multi-AZ | 지원 (Provisioned와 동일 failover) | [AWS Docs] |
| Global Database | 지원 | [AWS Docs] |
| RDS Proxy | 지원 (Lambda ↔ Aurora 연결 풀링 최적 조합) | [AWS Docs] |
| 미지원 | Database Activity Streams, Cluster Cache Management (Aurora PG), Aurora Auto Scaling (reader로 대체) | [AWS Docs] |
| Promotion Tier | 0-1은 writer와 동일 용량 추적, 2-15는 독립 스케일 | [AWS Docs] |

### 1.2 이행 관점 함의

- **동일 엔진(MySQL/PostgreSQL) 유지** = 마이그레이션 리스크 최소 — DDL·애플리케이션 SQL 대부분 그대로 승계. [AWS Docs]
- **바닥 비용 함정**: `min ACU > 0` 설정 시 idle 시에도 항상 과금. 완전 zero-idle 원할 경우 min=0 + auto-pause를 선택하되 resume 지연 감수. [AWS Docs]
- **burst 대응**: 0.5 ACU 단위의 초 단위 스케일로 Lambda 동시성 급증에 연동 가능. [AWS Docs]
- **v1과의 차이**: v1은 2배수 ACU 스텝·수 분 단위 스케일·콜드 스타트 존재 — v2 마이그레이션의 기본 이유. [AWS Docs]
- **혼합 운영 가능**: 동일 클러스터에 Provisioned + Serverless v2 인스턴스 동시 존재 가능. 점진 전환 경로로 유효. [AWS Docs]
- **Lambda와의 궁합**: RDS Proxy 경유 연결 풀링 조합이 표준. Proxy 없이 직접 연결 시 커넥션 폭주 위험. [AWS Docs]

## 2. RDS → DynamoDB

Primary citation: [AWS Docs — DynamoDB Read/Write Capacity Mode](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadWriteCapacityMode.html)

### 2.1 On-Demand vs Provisioned

| 항목 | On-Demand | Provisioned | 출처 |
|------|-----------|-------------|------|
| 청구 단위 | 요청당 (RRU/WRU) | 시간당 용량 예약 (RCU/WCU × hour) | [AWS Docs] |
| 1 RRU = | 최대 4KB strong-consistent read 1회 또는 eventually-consistent read 2회 | — | [AWS Docs] |
| 1 WRU = | 최대 1KB write 1회 | — | [AWS Docs] |
| 스케일링 | 자동, 신규 테이블도 즉시 4,000 writes/sec + 12,000 reads/sec | Auto Scaling (수 분 반응) | [AWS Docs] |
| 피크 대응 | 이전 피크 **2배**까지 즉시 허용 | burst capacity (5분) 완충 | [AWS Docs] |
| 바닥 비용 | 0 (호출 없으면 $0) | min × 가동시간 | [AWS Docs] |
| Reserved Capacity | 불가 | 1년 **최대 54%** / 3년 **최대 77%** 할인 (100 RCU/WCU 단위) | [AWS Docs] |
| 모드 전환 제한 | Provisioned → On-Demand: 24h당 최대 4회 | On-Demand → Provisioned: 언제든 | [AWS Docs] |
| 기본 쿼터 | 계정당 합산 **40,000 RCU/WCU**, On-Demand 테이블당 max 40,000 RCU + 40,000 WCU | 동일 | [AWS Docs] |
| per-table max | On-Demand에 설정 가능 (비용 폭주 방지) | — | [AWS Docs] |
| 적합 워크로드 | 예측 불가·스파이키·서버리스·신규 앱 | 안정·예측 가능·지속 고부하 + Reserved | [AWS Docs] |

### 2.2 Strong vs Eventual consistency

| 옵션 | RRU 비용 | 지연 | 용례 |
|------|----------|------|------|
| Strong-consistent read | 기본 (1 RRU / 4KB) | 약간 높음 | 금융·재고 |
| Eventually-consistent read | **절반** (0.5 RRU / 4KB) | 낮음 | 대부분의 읽기 |

이 두 모드의 선택이 DynamoDB 비용·성능 트레이드오프의 첫 번째 지렛대. [AWS Docs]

### 2.3 이행 관점 함의

- **데이터 모델 재설계 필수**: 관계형 JOIN 패턴은 DynamoDB 단일 테이블 설계로 재구성. 마이그레이션 리스크의 대부분이 여기서 발생. [AWS Docs]
- **시작은 On-Demand** — 예측 불가·신규 앱의 기본 권고. Lambda 동시성 확장과 자연 매칭. [AWS Docs]
- **정상 부하 확정 후 Provisioned로 전환**: Reserved Capacity로 On-Demand 대비 50~70% 절감 가능. 단 24h 전환 제한 고려. [AWS Docs]
- **GSI 별도 capacity mode**: GSI를 다른 capacity mode로 설정 가능 → 조회 빈도 차이 반영. [AWS Docs]
- **검증 사례**: openclaw는 DynamoDB에 대화 데이터를 저장하고 S3에 세션 백업을 두어 stateless Lambda의 지속성 문제를 해결. [Case: openclaw] [Insight #O4]
- **per-table max** 설정으로 비용 폭주 방지는 운영 기본값 — On-Demand의 "무한 스케일"이 곧 "무한 비용"이 되지 않도록. [AWS Docs]

## 3. S3 Standard vs S3 Express One Zone

Primary citation: [AWS Docs — S3 Express One Zone](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-express-one-zone.html)
보조: [AWS Docs — Directory buckets overview](https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-overview.html)

### 3.1 특성 비교

| 항목 | S3 Standard | S3 Express One Zone | 출처 |
|------|-------------|---------------------|------|
| AZ 스코프 | 리전 내 복수 AZ | **단일 AZ** (가용성 SLA 99.95%) | [AWS Docs] |
| 지연 시간 | 수십 ms | 한 자리 ms (~10× 저지연) | [AWS Docs] |
| 처리량 (버킷당) | prefix 단위 확장 | 읽기 200,000 TPS / 쓰기 100,000 TPS | [AWS Docs] |
| 버킷 타입 | General purpose | **Directory bucket** (별도 스키마) | [AWS Docs] |
| 버킷 네이밍 | 3-63자 | `{base}--{zone-id}--x-s3` 필수 | [AWS Docs] |
| 스토리지 구조 | flat prefix | 계층형 디렉토리 (slash로 폴더 자동 생성) | [AWS Docs] |
| 요청 가격 | 기본 | 약 **50% 저렴** | [AWS Docs] |
| 스토리지 가격 | 기본 | 단가 유사 — **비용 이점 주 원천은 요청 단가** | [AWS Docs] |
| 일관성 | Strong read-after-write | Strong read-after-write | [AWS Docs] |
| 암호화 | SSE-S3 / SSE-KMS / SSE-C | SSE-S3 / SSE-KMS (**SSE-C 미지원**) | [AWS Docs] |
| ACL | 선택 | 항상 bucket-owner-enforced | [AWS Docs] |
| Block Public Access | 선택 | **항상 On** | [AWS Docs] |
| 버저닝·CRR·Lifecycle | 완전 | 제한적 (버저닝·CRR 없음) | [AWS Docs] |
| 쿼터 | — | 계정당 리전별 디렉토리 버킷 **100개** (증가 가능) | [AWS Docs] |

### 3.2 이행 관점 함의

- **적합 워크로드**: 비디오 편집·ML 훈련 데이터 random access·실시간 분석·shuffle/spill·분석 중간 결과. [AWS Docs]
- **부적합**: 장기 아카이브·다중 리전 재해복구·규제 요구 다내구성 저장·CDN 오리진·ACL 필요 워크로드. [AWS Docs]
- **단일 AZ 제약**: AZ 장애 시 데이터 유실 가능 → 원본은 Standard/Glacier에 별도 보관, 중간 결과만 Express에. [AWS Docs]
- **비용 역전 함정**: 저빈도 접근 시 Standard 대비 **총비용 증가** — 요청 단가 절감은 요청 빈도에 비례. [AWS Docs]
- **AZ 동일 배치 필수**: EC2/Fargate/Lambda와 동일 AZ에서 접근해야 DTO 비용·지연 이득 실현. IaC에서 AZ 명시. [AWS Docs]
- **CreateSession 인증 모델**: 객체 오퍼레이션 전 `s3express:CreateSession` 필요 → SDK 최신 버전 + IAM 정책 업그레이드. [AWS Docs]
- **네이밍 규칙 자동화**: `--{zone-id}--x-s3` 패턴이 필수 — Terraform/CDK 템플릿에 강제. [AWS Docs]

## 4. Decision matrix

| 현재 상태 | 추천 타겟 | 리스크 | 근거 |
|-----------|-----------|--------|------|
| RDS MySQL/PostgreSQL (일반 OLTP) | Aurora Serverless v2 (min>0) | 낮음 | 동일 엔진 [AWS Docs §1] |
| RDS + 심한 idle 구간 | Aurora Serverless v2 (min=0 auto-pause) | 중 (resume 지연) | [AWS Docs §1.2] |
| Key-value access만 + 관계형 JOIN 없음 | DynamoDB On-Demand 시작 | 중 (모델 재설계) | [AWS Docs §2] |
| 예측 가능 고부하 DynamoDB 전환 | Provisioned + Reserved Capacity | 낮음 | 최대 77% 할인 [AWS Docs §2.1] |
| S3 Standard, 배치 읽기 과다 (훈련·shuffle) | + S3 Express 캐시층 (동일 AZ) | 낮음~중 | [AWS Docs §3] |
| S3 Standard, CDN 오리진·규제 저장 | 유지 | — | S3 Express 부적합 [AWS Docs §3.2] |
| 세션·대화 지속성 필요 (stateless Lambda) | DynamoDB + S3 백업 조합 | 낮음 | [Case: openclaw] [Insight #O4] |

## 5. 이행 패턴 preview

Tier 3 데이터 이행은 **검증 사례 없음**(SPEC §9). 원칙 수준 패턴만 존재:

- Strangler Fig + Branch by Abstraction으로 경로 분기
- CDC(Change Data Capture) 기반 점진 복제
- 읽기 먼저 이중화 → 쓰기 이중화 → 읽기 전환 → 쓰기 전환 → 폐기

→ 세부 단계는 [patterns-tier3-data.md](patterns-tier3-data.md) (Stage D에서 작성)
