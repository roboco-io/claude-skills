> **Snapshot date**: 2026-04-18
> **Lens publication**: 2022-07-14 (AWS 문서 최근 개정 확인 필요 — RESEARCH §12)
> **Description**: AWS Well-Architected Serverless Lens 설계원칙

# AWS Well-Architected Serverless Applications Lens

AWS Well-Architected Framework의 서버리스 특화 보완 문서. 본 스킬은 Lens를 **원칙 수준 체크포인트**로 활용하여 Phase 4 타겟 추천·Tradeoff Dossier·Delegation 섹션의 근거로 인용한다.

## 1. 7 Design Principles

> **수집 노트**: 원래 "9 design principles"를 기대했으나, 2026-04-18 기준 AWS Serverless Lens 공식문서(`general-design-principles.html`)는 **7개 원칙**만 공식 수록. `design-principles.html` 엔드포인트는 빈 페이지로 리다이렉트됨. 아래 표는 현행 공식 문서의 원문 제목(verbatim)과 요약(원문 1문장) 인용. [RESEARCH §12]

| # | Principle (원문) | 요약 (원문) | 본 스킬에서의 활용 |
|---|-----------------|------------|-------------------|
| 1 | Speedy, simple, singular | Functions are concise, short, single-purpose, and their environment may live up to their request lifecycle. | Phase 2 워크로드 특성 평가 기준 (함수 단위 분해 가능성) |
| 2 | Think concurrent requests, not total requests | Serverless applications take advantage of the concurrency model, and tradeoffs at the design level are evaluated based on concurrency. | Phase 3 RPS → Lambda 동시성 쿼터 매핑 |
| 3 | Share nothing | Function runtime environment and underlying infrastructure are short-lived, therefore local resources such as temporary storage is not guaranteed. | Phase 2 상태 저장성 평가 (S3/DynamoDB 위임 트리거) |
| 4 | Assume no hardware affinity | Underlying infrastructure may change. Use code or dependencies that are hardware-agnostic. | Phase 4 타겟 런타임 선정 (GPU/특수 CPU 의존은 비적합) |
| 5 | Orchestrate your application with state machines, not functions | Chaining Lambda executions within the code to orchestrate the workflow of your application results in a monolithic and tightly coupled application. Instead, use a state machine to orchestrate transactions and communication flows. | Phase 4 Step Functions 도입 권고 근거 |
| 6 | Use events to trigger transactions | Events such as writing a new Amazon S3 object or an update to a database allow for transaction execution in response to business functionalities. | Phase 4 EventBridge/SQS 기반 이벤트 드리븐 전환 근거 |
| 7 | Design for failures and duplicates | Operations triggered from requests or events must be idempotent, as failures can occur and a given request or event can be delivered more than once. | Phase 4 멱등성 요구 (Spot 인터럽트 재시도와 결합) |

**주**: 본래 9개였으나 2026-04-18 기준 AWS 공식 페이지는 7개만 유지. 변경 추적은 `references/serverless-lens.md`의 Snapshot date와 함께 수동 리뷰. [AWS Docs]

## 2. 5 Pillars — Serverless 특화 Best Practice

Well-Architected 5대 기둥의 서버리스 특화 질문·베스트프랙티스 요지.

### 2.1 Operational Excellence [AWS Docs §WA-OPS]
- 배포 자동화: IaC + canary/linear 배포 + 자동 롤백
- 모니터링: 함수 단위 메트릭 + X-Ray 분산 추적 + 구조화 로깅
- 경고: 실패율·p99 지연·동시성 포화에 기반한 알람

### 2.2 Security [AWS Docs §WA-SEC]
- IAM **최소권한** — 함수 단위 역할 분리
- 이벤트 소스 **검증** — API Gateway WAF·EventBridge event pattern·SQS VisibilityTimeout
- 비밀 관리 — Secrets Manager / Parameter Store, 환경변수 평문 금지

### 2.3 Reliability [AWS Docs §WA-REL]
- **멱등성 처리** (원칙 #7과 직결)
- DLQ / redrive — SQS·EventBridge·Lambda 모두 지원
- 재시도 정책 — Lambda 비동기 2회·EventBridge 최대 185회 [tradeoffs-event-driven.md §1.2]
- 멀티 AZ 전제 (Lambda/Aurora SV2/DynamoDB 모두 기본)

### 2.4 Performance [AWS Docs §WA-PERF]
- **콜드 스타트 완화**: Provisioned Concurrency / SnapStart (배타) [tradeoffs-compute.md §1.2]
- 메모리·CPU 튜닝 (1,769 MB = 1 vCPU) [AWS Docs]
- 연결 풀링 — RDS Proxy, HTTP keepalive
- 캐싱 — API Gateway cache, DAX, ElastiCache

### 2.5 Cost [AWS Docs §WA-COST]
- **HUGI (Hurry Up and Get Idle)** — billable ≠ wall clock [tradeoffs-spot.md §4]
- **서비스 우선, 서버 아님** — 관리형 서비스로 고정비 제거
- 데이터 전송 비용: 동일 AZ 배치, CloudFront 활용
- 검증 사례: `autoresearch` 48 실험 $3.94, `openclaw` ~$1/월 [Case: autoresearch] [Case: openclaw]

## 3. 본 스킬과 Lens의 매핑

본 스킬의 5 Phase 출력물에서 Lens 원칙을 직접 인용하여 의사결정 근거로 제시.

| 본 스킬 Phase | 활용 원칙 | 활용 형태 |
|--------------|-----------|-----------|
| Phase 1 (워크로드 분류) | #1 Speedy, simple, singular / #3 Share nothing | 함수 단위 분해 가능 여부 인터뷰 질문의 이론 근거 |
| Phase 3 (제약 심층) | #2 Think concurrent requests | RPS → Lambda 동시성 쿼터 매핑 질문 |
| Phase 4 (타겟 추천) | #2 Services not servers (Pillar Cost) · #4 Use purpose-built data stores | 매핑 테이블의 **선택 근거** 칼럼 |
| Phase 4 (Step Functions 권고) | #5 Orchestrate with state machines | Lambda 체이닝 탈피 권고의 정당화 |
| Phase 4 (EventBridge/SQS) | #6 Use events to trigger transactions | 이벤트 드리븐 전환 권고 |
| Tradeoff Dossier | #7 Design for failures and duplicates | 멱등성·DLQ 리스크 섹션의 필수 체크 |
| Delegation | #1 Speed up your development cycle (Pillar Operational Excellence) | IaC 자동화 제안의 이론 근거 |

## 4. Snapshot 갱신 정책

- **트리거**: Lens 공식 페이지 개정, 원칙 추가·삭제, 또는 6개월 주기 리뷰.
- **갱신 대상**: 본 파일 상단의 `Lens publication` 및 `Snapshot date`, §1 표 원문, RESEARCH §12.
- **버전 추적**: Git log로 이 파일의 변경 이력 관리. SPEC §14 오픈 질문 4번 항목.

## 5. Reference links

- [AWS Well-Architected Framework](https://aws.amazon.com/well-architected/) [AWS Docs]
- [Serverless Applications Lens — Welcome](https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/welcome.html) [AWS Docs]
- [Design Principles (general)](https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/general-design-principles.html) [AWS Docs]
- [The Pillars of the Well-Architected Framework (serverless lens)](https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/the-pillars-of-the-well-architected-framework.html) [AWS Docs]

---

*본 파일은 `aws-well-architected` 스킬(리뷰 관점)과 역할 분리됨 — 본 스킬은 **이행 관점**에서 Lens를 체크포인트로 사용. SPEC §13.*
