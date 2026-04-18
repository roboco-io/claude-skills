# Issue #3: Serverless Migration Advisor — 구현 계획

> **전제**: `SPEC.md` 승인 후 착수.
> **구현 위치**: `plugins/workflow/skills/serverless-migration-advisor/`.
> **총 예상 공수**: ~2.5일(1인). 리서치 1일 + 본문 작성 1일 + references + 검증 0.5일.

## 0. 선행 조건

- [x] HANDOFF.md 숙독
- [x] SPEC.md 작성 완료
- [x] SPEC.md / PLAN.md / RESEARCH.md 사용자 승인 — **Stage 1 시작 전 필수**
- [x] 기존 sagemaker-spot-training 스킬 인터페이스 확인
- [x] 두 검증 프로젝트 경로 확보 (autoresearch, openclaw)
- [x] AWS 공식문서 1차 수집 완료 (RESEARCH.md 참고)

---

## 1. 구현 단계

### Stage 1 — 리서치 보강 (0.5일)

목표: `RESEARCH.md`의 공식문서 스냅샷을 references/*.md로 구조화 가능한 수준까지 완성.

**Tasks:**

1. **AWS Serverless Lens 9개 설계원칙 전체 발췌**
   - 출처: https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/design-principles.html
   - 각 원칙에 한 줄 요약 + 본 스킬에서의 활용처 매핑.
2. **Aurora Serverless v2 / DynamoDB 트레이드오프**
   - Aurora Serverless v2: ACU 스케일링 특성, Cold start 없음, 최소 ACU 비용 바닥.
   - DynamoDB: On-Demand vs Provisioned, 단일 테이블 설계 트레이드오프.
3. **EventBridge / SQS / Step Functions** 비교
   - 이벤트 역전(invert)  보장, 재시도, DLQ, 비용 단위.
4. **S3 Express One Zone** — 저지연 배치 워크로드 용도.
5. **Lambda SnapStart** (Java/Python) — 콜드 스타트 대안.
6. **검증 사례 재리뷰**
   - `serverless-autoresearch/docs/insights.md` — 15개 인사이트 번호 고정.
   - `serverless-openclaw/` — 비용 구조, Lambda Container 1.35s, EventBridge pre-warming 로직.

**Deliverable**: 본 계획과 동일 디렉토리의 `RESEARCH.md` 업데이트.

---

### Stage 2 — 스킬 스켈레톤 생성 (0.5일)

**Tasks:**

1. 디렉토리 생성:
   ```
   plugins/workflow/skills/serverless-migration-advisor/
   ├── SKILL.md
   └── references/
   ```
2. `SKILL.md` 초안 작성 (YAML frontmatter + 5 Phase 골격):
   - `name: serverless-migration-advisor`
   - `description:` — 트리거 키워드("서버리스 이행", "EC2에서 Lambda로", "Spot 이행", "serverless migration") 포함.
3. `references/` 파일 13개를 빈 스켈레톤으로 생성:
   - 각 파일 상단에 frontmatter 한 줄 + `> Snapshot date: 2026-04-18`.
   - Stage 3-5에서 내용 채움.
4. `plugin.json`, `marketplace.json` 업데이트:
   - workflow 플러그인의 `skills` 배열에 `./skills/serverless-migration-advisor/SKILL.md` 추가.
5. `README.md` 플러그인 목록 갱신.

**Verification**: `npm test` 통과 (marketplace·plugin-json·skills·integrity 검증).

---

### Stage 3 — 트레이드오프 references 채우기 (0.5일)

우선순위 순:

1. **`tradeoffs-compute.md`** ← SPEC §4.1-4.5 내용을 확장.
   - Lambda, SageMaker Spot, Fargate Spot, EC2 Spot, Batch 각 섹션.
   - 표 + "함의" + 공식 URL 링크.
2. **`tradeoffs-spot.md`**
   - 용량(placement score), 가격, 인터럽트 동작(`terminate`/`stop`/`hibernate`), HUGI, billable 정의.
   - `aws ec2 get-spot-placement-scores` 예시 명령.
3. **`serverless-lens.md`**
   - 9개 설계원칙 한 줄 요약.
   - "이 스킬에서의 활용" 매핑 테이블.
4. **`tradeoffs-data-layer.md`** — Tier 3용.
5. **`tradeoffs-event-driven.md`** — 이벤트 기반 재설계용.

**원칙**: 각 파일에 최소 3개 공식 URL 인용. 주장당 한 줄 인용(`> AWS Docs: …`).

---

### Stage 4 — 이행 패턴 references 채우기 (0.5일)

1. **`patterns-tier1-batch.md`**
   - EC2 long-running → SageMaker Managed Spot.
   - EMR → AWS Batch + Fargate/EC2 Spot.
   - Cron on EC2 → EventBridge Scheduler + Lambda/Batch.
   - 각 패턴: before/after diagram (텍스트), 체크리스트 템플릿, autoresearch Insight 인용.
2. **`patterns-tier2-api.md`**
   - ALB + EC2 → API Gateway + Lambda.
   - ECS 상시 서비스 → Fargate + Fargate Spot 혼합.
   - WebSocket → API Gateway WebSocket + Lambda.
   - openclaw 사례 인용.
3. **`patterns-tier3-monolith.md`**
   - Strangler Fig (AWS 공식 prescriptive guidance 링크).
   - Branch by Abstraction.
   - "Tier 3는 검증 사례 없음 — 파일럿 필수" 경고.
4. **`patterns-tier3-data.md`**
   - RDS → Aurora Serverless v2 (동일 엔진 유지 이행).
   - RDS → DynamoDB (모델 재설계 필요, CDC 기반).
   - S3 Express One Zone 도입 전략.

---

### Stage 5 — 검증 사례 + 인사이트 references (0.25일)

1. **`case-study-autoresearch.md`**
   - 프로젝트 링크, 커밋 해시, 핵심 숫자 테이블.
   - 본 스킬 출력에서 인용 가능한 "범위 문자열" (예: "H100 Spot 229s $0.16").
2. **`case-study-openclaw.md`**
   - 프로젝트 링크, 아키텍처 요약, 비용 구조.
   - "Tier 2 상시형 API $1/월 달성 사례" 앵커.
3. **`source-insights.md`**
   - autoresearch 15개 + openclaw 주요 인사이트 번호화.
   - 번호 고정 규칙: 초기 순서 유지, 추가 시만 번호 증가.

---

### Stage 6 — 인터뷰 뱅크 + SKILL.md 본문 (0.5일)

1. **`interview-bank.md`**
   - Phase 1/3별 질문 집합 완성.
   - Tier별 분기 규칙 명시.
   - 각 질문에 AskUserQuestion JSON 형식 템플릿.
2. **`SKILL.md` 본문 완성**
   - 5 Phase 실행 순서.
   - 각 Phase에서 참조할 references 파일 명시.
   - 리포트 템플릿 (SPEC §5).
   - Delegation 로직.
   - 500줄 이하 유지, 상세는 references로.

---

### Stage 7 — 테스트 및 통합 (0.25일)

1. **Unit 테스트**
   - `src/__tests__/skills.test.ts`가 자동으로 본 스킬 검증 (frontmatter, 파일 존재, 줄수).
   - `integrity.test.ts` — marketplace↔plugin.json↔SKILL.md 정합성.
   - `npm test` green.
2. **통합 검증**
   - 로컬 설치: `/plugin marketplace add <path>` → `/plugin install workflow@roboco-plugins`.
   - 샘플 시나리오 3개 돌려보기:
     - Tier 1: "EC2 H100 야간 배치 → Spot 이행"
     - Tier 2: "ALB + EC2 상시 API → Lambda 이행"
     - Tier 3: "모놀리스 RDS → DynamoDB 분해"
   - 각 시나리오에서 리포트 생성 정상 여부 확인.
3. **Delegation 동작**
   - Tier 1 시나리오에서 `sagemaker-spot-training` 스킬이 트리거되거나 최소한 안내되는지 확인.

---

### Stage 8 — 문서화 및 출시 (0.25일)

1. `CHANGELOG.md` 업데이트 (`0.3.0-beta` 또는 결정된 버전).
2. `README.md` 플러그인 목록 테이블 최종 확인.
3. 커밋 (TiDD 준수 — 이슈 #3 연결):
   - `feat(workflow): add serverless-migration-advisor skill (#3)`
4. PR 생성.

---

## 2. 리스크 및 완화

| 리스크 | 영향 | 완화 |
|-------|------|------|
| Serverless Lens 문서 링크가 끊기거나 개정됨 | 인용 traceability 훼손 | `references/serverless-lens.md`에 `Snapshot date` 기재, 6개월 주기 리뷰 |
| Tier 3 범위가 과도하게 팽창 | 일정 초과, 스킬 품질 저하 | "원칙 수준만" 가이드 고수, 상세는 AWS 공식 링크로 회피 |
| AskUserQuestion이 많으면 UX 저하 | 사용자 이탈 | Phase 1 4문항, Phase 3은 분기로 평균 4-5문항 유지 |
| sagemaker-spot-training과 중복 | 두 스킬이 동일 질문 반복 | 본 스킬은 "서비스 확정까지", 구현은 무조건 위임 |
| aws-well-architected와 중복 | 리뷰/이행 혼선 | 본 스킬 SKILL.md 상단에 "이 스킬은 이행, WA는 리뷰" 명시 |

---

## 3. 의사결정이 필요한 지점 (구현 중)

- **IaC 정적 분석 수준**: Phase 2에서 Terraform/CDK 파싱. 첫 버전은 정규식 기반으로 `resource "aws_instance"` 같은 패턴만 추출. 파서 라이브러리 도입은 후속.
- **리포트 슬러그 충돌 규칙**: `YYYY-MM-DD-<topic>` 중복 시 `-2`, `-3` 접미사 부여 함수.
- **언어**: 리포트 기본 언어는 사용자 대화 언어 자동 감지. SKILL.md 본문·references는 한국어.
- **검증 사례 인용 빈도**: 리포트 한 건당 최소 1개 Case + 최소 2개 Insight + 최소 3개 AWS Docs 링크.

---

## 4. 산출물 체크리스트

- [x] `plugins/workflow/skills/serverless-migration-advisor/SKILL.md`
- [x] `references/tradeoffs-compute.md`
- [x] `references/tradeoffs-spot.md`
- [x] `references/tradeoffs-data-layer.md`
- [x] `references/tradeoffs-event-driven.md`
- [x] `references/serverless-lens.md`
- [x] `references/patterns-tier1-batch.md`
- [x] `references/patterns-tier2-api.md`
- [x] `references/patterns-tier3-monolith.md`
- [x] `references/patterns-tier3-data.md`
- [x] `references/interview-bank.md`
- [x] `references/case-study-autoresearch.md`
- [x] `references/case-study-openclaw.md`
- [x] `references/source-insights.md`
- [x] `.claude-plugin/marketplace.json` 업데이트
- [x] `README.md` 목록 업데이트
- [x] `CHANGELOG.md` 업데이트
- [ ] `npm test` green
- [ ] 로컬 설치 후 3개 시나리오 실행 통과

---

## 5. 수락 기준

SPEC §12의 6개 지표 + 다음:

- [ ] `npm test` 전부 green
- [ ] SKILL.md 500줄 이하
- [ ] 모든 references/*.md에 `Snapshot date` 표기
- [ ] 모든 트레이드오프 주장에 `[AWS Docs]` 또는 `[Insight #N]` 또는 `[Case: …]` 라벨
- [ ] Tier별 샘플 3개 모두 리포트 생성 성공
- [ ] `sagemaker-spot-training` 위임 경로 동작

---

*본 계획 생성: 2026-04-18. SPEC 승인 후 본 파일 기준으로 구현 착수.*
