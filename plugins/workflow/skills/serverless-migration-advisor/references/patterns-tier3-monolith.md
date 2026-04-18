> **Snapshot date**: 2026-04-18
> **Tier**: 3 (모놀리스 분해) — **검증 사례 없음**
> **Description**: Strangler Fig 기반 모놀리스 분해

# Tier 3 Migration Patterns — Monolith Decomposition

> ⚠️ **Tier 3 검증 경고**
>
> 본 스킬이 참조하는 두 검증 사례(serverless-autoresearch, serverless-openclaw)는 Tier 3 이행을 직접 검증하지 않았습니다. 본 문서는 AWS 공식 prescriptive guidance + 원칙 수준 가이드만 제공합니다.
>
> 대규모 프로젝트 적용 전 **필수**:
> 1. 서비스 경계(Bounded Context) 식별
> 2. 파일럿 서비스 1~2개로 소규모 검증
> 3. 실제 트래픽·장애·롤백 시나리오 리허설
>
> Strangler Fig / Branch by Abstraction은 2년 이상 소요되는 대형 이행이 일반적이며, 스킬이 체크리스트 수준으로 제시하는 것 이상을 이 문서에서 자동화하지 않습니다.
>
> SPEC §9 "Tier 3 취급 방침"과 일관: 원칙 수준 패턴 + AWS Docs 링크 + 파일럿 권고까지.

## 1. Scope of this document

**포함**:
- Strangler Fig / Branch by Abstraction의 **원칙** 수준 가이드
- AWS prescriptive guidance 링크
- "무엇을 하면 안 되는가"의 Do/Don't

**미포함**:
- 서비스 경계 식별 자동화
- 구체적 before/after 다이어그램 (각 조직의 모놀리스 구조 의존도가 너무 큼)
- 단계별 비용·기간 추정 (검증 데이터 없음)
- IaC diff 제안

본 스킬의 출력은 **"Tier 3임을 식별하고 AWS Docs와 파일럿 권고로 이어지는 bridge"** 역할에 국한됩니다.

## 2. Applicable approaches (원칙 수준)

### Approach 3.1: Strangler Fig Application

**원칙**:
- 기존 모놀리스 뒤에 neutral routing 레이어(API Gateway 또는 ALB path-based routing) 배치
- 신규 기능 또는 추출 대상 기능만 서버리스 컴포넌트로 분리
- 기존 모놀리스는 **그대로 유지**하며, 점진적으로 라우팅을 새 컴포넌트로 이관
- 최종적으로 모놀리스에 잔존 코드가 없을 때 폐기

**관련 AWS 서비스**:
- **Routing 레이어**: API Gateway (HTTP/REST API, 경로별 target), ALB path-based routing, CloudFront origins
- **신규 capabilities**: Lambda (Tier 2 패턴), Fargate (상시 서비스), Step Functions (워크플로)
- **데이터 분리**: DynamoDB, Aurora Serverless v2 (서비스별 DB — [patterns-tier3-data.md](patterns-tier3-data.md) §Pattern 4.1-4.2)

**AWS prescriptive guidance**: [Monolith deconstruction strategy](https://docs.aws.amazon.com/prescriptive-guidance/latest/modernization-aspnet-web-services/monolith-deconstruction-strategy.html)

### Approach 3.2: Branch by Abstraction

**원칙**:
- 코드 내부에 **추상화 레이어(interface)** 도입
- 기존 구현(모놀리스 메서드) 뒤에 새 구현(서버리스 함수 호출)을 병렬 배치
- feature flag로 트래픽 비율 이동 → 안전성 검증 후 이전 구현 폐기
- Strangler Fig가 **네트워크 경계**의 점진적 대체라면 Branch by Abstraction은 **코드 경계**의 점진적 대체

**서버리스 관점**:
- 추상화의 대체 구현이 Lambda 함수 호출 또는 Fargate task API 호출이 될 수 있음
- 결제·인증 등 복잡한 내부 서비스 추출에 적합

**상호 보완**: Strangler Fig + Branch by Abstraction을 결합 가능. 외부 경계는 Strangler Fig (API Gateway routing), 내부 호출은 Branch by Abstraction (코드 interface)로 전환.

### Approach 3.3: Database-per-service 이전

**원칙**:
- 서비스 분리 시 **데이터도 분리** — 공유 DB를 유지한 채 서비스만 쪼개는 것은 분산 모놀리스를 만들 위험
- 서비스별 소유 DB를 선언하고, 다른 서비스가 필요로 하는 데이터는 **이벤트 또는 API**로 제공
- CDC(Change Data Capture)로 기존 모놀리스 DB → 서비스별 DB 점진 이전

**관련 AWS 서비스·문서**:
- DMS (CDC 기반 이전): [patterns-tier3-data.md §Pattern 4.2](patterns-tier3-data.md)
- EventBridge (서비스 간 이벤트): [tradeoffs-event-driven.md §1](tradeoffs-event-driven.md)
- Saga 패턴 (Step Functions Standard): [tradeoffs-event-driven.md §4](tradeoffs-event-driven.md)

**AWS prescriptive guidance**: [Database-per-service 패턴은 Strangler Fig 문맥에서 함께 다뤄짐](https://docs.aws.amazon.com/prescriptive-guidance/latest/modernization-data-persistence/strangler-fig.html)

### Approach 3.4: Observability-first

**원칙**:
- 모놀리스 분해 **이전에** 관측 가능성(로그·메트릭·트레이싱) 먼저 확보
- 경계를 모르는 상태에서 분해 시작 시 장애 원인 파악 불가
- X-Ray 트레이싱을 모놀리스 단계에서 도입 → 분해 후에도 호출 경로 추적 유지

**관련 AWS 서비스**:
- AWS X-Ray (distributed tracing)
- CloudWatch Logs Insights (구조화 로그 쿼리)
- CloudWatch Contributor Insights (top-N 경로 분석)

## 3. Do / Don't

| Do | Don't |
|----|-------|
| 1-2개 bounded context 파일럿부터 시작 | 전체 모놀리스 동시 분해 시도 |
| 신규 기능을 **서버리스로 먼저** 구현 | 기존 기능 재작성 우선 |
| API Gateway / ALB path routing으로 routing 제어 | DNS 기반 분할 (TTL·캐시 복잡도) |
| 추출 전 observability 확보 | 분해 후 관측 (원인 파악 불가) |
| 서비스 경계 = 데이터 경계 원칙 준수 | 공유 DB 유지하며 서비스만 분리 (분산 모놀리스) |
| 서비스 간 비동기 이벤트 (EventBridge) | 동기 RPC 체인으로 묶기 (연쇄 장애) |
| feature flag로 롤백 가능한 전환 | 빅뱅 전환 (컷오버 실패 시 대안 없음) |
| 서비스별 독립 배포 파이프라인 | 모놀리스 파이프라인에 새 서비스 붙이기 |
| 파일럿의 실패 시나리오·롤백 리허설 | 검증 없이 프로덕션 적용 |

## 4. 의사결정 질문 (Phase 3 인터뷰 보조)

본 스킬이 Tier 3로 분류한 사용자에게 Phase 3에서 묻는 질문:

- **Q**: 분해 목표 서비스는 1-2개로 한정 가능한가?
  - Yes → Strangler Fig 파일럿 경로 추천
  - No (전체 재작성) → **권장 중단** — 재작성 대신 신규 기능만 서버리스로 추가하는 방향 제안

- **Q**: 현재 모놀리스의 X-Ray 트레이싱·구조화 로그 커버리지?
  - 충분 → 분해 준비 가능
  - 부족 → **Stage 0을 "observability 확보"로 고정** — 분해 시작 연기

- **Q**: 서비스 경계 후보의 bounded context가 식별되었나?
  - Yes (DDD workshop 등 완료) → 진행
  - No → 진행 전 **DDD 발견 workshop** 권장 — 경계 없는 분해는 분산 모놀리스 생산

- **Q**: 다운타임 윈도우?
  - 무 (24/7 전환) → feature flag + Strangler Fig 필수
  - 유 (주기적 유지보수 윈도우) → blue/green 컷오버 가능하나 **여전히 파일럿 권장**

- **Q**: 데이터 일관성 요구?
  - Strong (금융 · 재고) → Step Functions Standard + Saga 패턴 ([tradeoffs-event-driven.md §4](tradeoffs-event-driven.md))
  - Eventual 허용 → EventBridge 기반 이벤트 전파로 충분

- **Q**: 벤더 락인 허용도?
  - High (AWS 전면 수용) → Lambda · DynamoDB 적극 활용
  - Low (이식성 우선) → Fargate 중심 컨테이너 분해 (Pattern 2.2) 권장

## 5. 이 스킬의 역할 제한

- Tier 3 이행 **상세 체크리스트** 제공하지 않음 — 각 조직의 상황 의존도가 너무 크다
- 서비스 경계 식별 **자동화** 시도하지 않음 — bounded context 결정은 도메인 전문가의 workshop이 필요
- 단계별 비용·기간 **추정하지 않음** — 검증 데이터 없음 (SPEC §9)
- 본 스킬의 출력은 "Tier 3임을 식별하고 AWS Docs와 파일럿 권고로 이어지는 bridge" 역할에 국한
- 구체적 "어떻게 분해할지"는 사용자·도메인 전문가 의사결정 영역이며, 본 스킬은 그 **결정에 필요한 AWS 서비스 선택지만 제시**

## 6. Citations

### AWS 공식문서

- [AWS prescriptive guidance — Monolith deconstruction strategy](https://docs.aws.amazon.com/prescriptive-guidance/latest/modernization-aspnet-web-services/monolith-deconstruction-strategy.html)
- [AWS prescriptive guidance — Strangler Fig in data persistence](https://docs.aws.amazon.com/prescriptive-guidance/latest/modernization-data-persistence/strangler-fig.html)
- [AWS prescriptive guidance — Decompose monoliths into microservices](https://docs.aws.amazon.com/prescriptive-guidance/latest/modernization-decomposing-monoliths/welcome.html)
- [AWS Well-Architected — Microservices implementation](https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html)

### 내부 cross-refs

- [patterns-tier3-data.md](patterns-tier3-data.md) — 데이터 레이어 이행 패턴
- [patterns-tier2-api.md](patterns-tier2-api.md) — 추출된 서비스의 타겟 패턴
- [tradeoffs-compute.md](tradeoffs-compute.md) — 서비스별 compute 트레이드오프
- [tradeoffs-event-driven.md §1, §4](tradeoffs-event-driven.md) — EventBridge · Step Functions 선택
- [serverless-lens.md](serverless-lens.md) — 원칙 3 "Share nothing", 원칙 5 "State machines", 원칙 6 "Events", 원칙 7 "Design for failures"

### 외부 참조 (스킬 사용자 자율 판단)

- [Martin Fowler — StranglerFigApplication](https://martinfowler.com/bliki/StranglerFigApplication.html)
- [Martin Fowler — BranchByAbstraction](https://martinfowler.com/bliki/BranchByAbstraction.html)

---

*본 문서는 Tier 3 의사결정 시 **안전 경고 + 원칙 정리 + AWS Docs 링크**의 세 가지 역할에 한정. 실제 이행은 조직별 파일럿을 전제로 한다.*
