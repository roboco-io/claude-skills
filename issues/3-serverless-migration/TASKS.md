# Serverless Migration Advisor — Implementation Tasks

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `plugins/workflow/skills/serverless-migration-advisor/` — an upstream advisor skill that interviews users about always-on workloads and outputs a traceable serverless+Spot migration plan, citing AWS Docs and two validated case studies.

**Architecture:** Single orchestrator SKILL.md + 13 focused `references/*.md` files. 5-Phase interaction: classification interview → IaC scan → tradeoff interview → target-arch mapping → report generation. Delegates implementation how-to to `sagemaker-spot-training` and future sibling skills.

**Tech Stack:** Markdown (SKILL + references), YAML frontmatter, existing Vitest harness (`src/__tests__/skills.test.ts`, `integrity.test.ts`, `marketplace.test.ts`, `plugin-json.test.ts`). No runtime code.

---

## File Structure

```
plugins/workflow/
├── .claude-plugin/plugin.json                           # MODIFY — bump version if needed
└── skills/
    └── serverless-migration-advisor/                    # CREATE
        ├── SKILL.md                                     # CREATE — ≤500 lines, 5-Phase orchestrator
        └── references/                                  # CREATE
            ├── tradeoffs-compute.md                     # Lambda/Fargate/Batch/SageMaker/EC2 Spot limits
            ├── tradeoffs-spot.md                        # Spot capacity/interrupt/HUGI/billable
            ├── tradeoffs-data-layer.md                  # RDS/Aurora Serverless v2/DynamoDB/S3 Express
            ├── tradeoffs-event-driven.md                # EventBridge/SQS/Kinesis/Step Functions
            ├── serverless-lens.md                       # WA Serverless Lens 9 design principles
            ├── patterns-tier1-batch.md                  # Batch/ETL/training migration patterns
            ├── patterns-tier2-api.md                    # Always-on API migration patterns
            ├── patterns-tier3-monolith.md               # Strangler Fig / decomposition
            ├── patterns-tier3-data.md                   # RDS→DynamoDB / CDC migration
            ├── interview-bank.md                        # AskUserQuestion templates by phase
            ├── case-study-autoresearch.md               # Tier 1 case study
            ├── case-study-openclaw.md                   # Tier 2 case study
            └── source-insights.md                       # Numbered insights from both cases

.claude-plugin/marketplace.json                          # MODIFY — add skill to workflow.skills
README.md                                                # MODIFY — add to Workflow skills table
CHANGELOG.md                                             # MODIFY — new entry
```

**Global test command** (use after every stage): `npm test`
**Global dev-loop**: `npx vitest` (watch mode)

---

## Stage A — Research Top-Up (prerequisite to writing references)

Goal: Fill gaps in `RESEARCH.md` so references/ can be authored without further lookups.

### Task A1: Serverless Lens 9 design principles

**Files:**
- Modify: `issues/3-serverless-migration/RESEARCH.md` (append §12)

- [ ] **Step 1: WebFetch design-principles page**

Run (as tool call):
```
WebFetch({
  url: "https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/design-principles.html",
  prompt: "List each of the 9 serverless design principles with the exact title and a one-sentence summary. Preserve numbering."
})
```
Expected: 9 numbered principles.

- [ ] **Step 2: Append §12 to RESEARCH.md**

Append a new section:

```markdown
## 12. Serverless Lens — 9 Design Principles (verbatim titles, paraphrased summaries)

| # | Title | Summary | 본 스킬에서의 활용 |
|---|-------|---------|-------------------|
| 1 | … | … | Phase 4 타겟 선택 근거 |
| … | … | … | … |
```

Fill from fetch result. Each row must cite the principle title verbatim.

- [ ] **Step 3: Commit**

```bash
git add issues/3-serverless-migration/RESEARCH.md
git commit -m "research(serverless-migration): add WA Serverless Lens 9 design principles (#3)"
```

### Task A2: Lambda SnapStart + Aurora Serverless v2 + DynamoDB + S3 Express + Step Functions

**Files:**
- Modify: `issues/3-serverless-migration/RESEARCH.md` (append §13-17)

- [ ] **Step 1: Parallel WebFetch (5 calls in one message)**

Fetch these URLs in parallel:
- `https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html` — "Extract SnapStart supported runtimes, restore latency range, excluded features (VPC ENI lifecycle, uniqueness pitfalls), and cost model."
- `https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2.html` — "Extract ACU range, scaling granularity, cold-start behavior vs v1, minimum capacity pricing floor, compatibility with provisioned."
- `https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadWriteCapacityMode.html` — "Compare On-Demand vs Provisioned capacity: billing units, auto-scaling, when to prefer each."
- `https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-express-one-zone.html` — "Extract S3 Express One Zone characteristics: AZ scope, latency claims, pricing model differences, directory bucket naming rules, workloads recommended vs not."
- `https://docs.aws.amazon.com/step-functions/latest/dg/concepts-standard-vs-express.html` — "Compare Standard vs Express workflows: max duration, execution history, pricing, at-least-once vs exactly-once, throughput."

- [ ] **Step 2: Append §13-17 to RESEARCH.md**

Each section follows the citation format already established in §2-6 (fact table + 함의 bullet list + URL at top).

- [ ] **Step 3: Commit**

```bash
git add issues/3-serverless-migration/RESEARCH.md
git commit -m "research(serverless-migration): add SnapStart/Aurora/DynamoDB/S3-Express/Step-Functions (#3)"
```

### Task A3: Case study fact extraction — autoresearch

**Files:**
- Modify: `issues/3-serverless-migration/RESEARCH.md` (§10.1 확장)

- [ ] **Step 1: Read autoresearch insights.md fully**

Run:
```
Read({ file_path: "/Users/dohyunjung/Workspace/roboco-io/research/serverless-autoresearch/docs/insights.md" })
```

- [ ] **Step 2: Read comparison-report.md and experiments/003-h100-comparison/results-summary.md**

Parallel reads.

- [ ] **Step 3: Rewrite §10.1 with numbered insight titles (1-15)**

Each row:
```markdown
| # | Title | One-line lesson | Tier usage |
|---|-------|-----------------|------------|
| 1 | Spot Capacity Varies Dramatically by Region | 동일 인스턴스 타입도 리전마다 placement score 1~9 편차 | Tier 1 배치 |
| … | … | … | … |
```

Record commit hash at the end of §10.1: `(Snapshot: git rev-parse HEAD in autoresearch)`.

- [ ] **Step 4: Commit**

```bash
git add issues/3-serverless-migration/RESEARCH.md
git commit -m "research(serverless-migration): extract 15 autoresearch insights with tier mapping (#3)"
```

### Task A4: Case study fact extraction — openclaw

**Files:**
- Modify: `issues/3-serverless-migration/RESEARCH.md` (§10.2 확장)

- [ ] **Step 1: Fetch openclaw README + architecture docs**

```
WebFetch({
  url: "https://github.com/serithemage/serverless-openclaw",
  prompt: "Extract the architecture: compute choices (Lambda Container primary, ECS Fargate Spot fallback), cost breakdown ($1-2/month, Free Tier $0.23), cold start numbers (1.35s), pre-warming strategy (EventBridge scheduled), API Gateway vs ALB savings ($18-25/month)."
})
```

- [ ] **Step 2: Expand §10.2**

Add a principles-extracted table:

```markdown
| # | Principle from openclaw | Tier usage |
|---|------------------------|------------|
| O1 | Lambda Container + dual compute fallback | Tier 2 API |
| O2 | API Gateway over ALB to eliminate $18-25/mo baseline | Tier 2 API |
| O3 | EventBridge scheduled pre-warming during active hours | Tier 2 API |
| O4 | S3 session persistence for stateless Lambda | Tier 2 API |
| O5 | CloudFront + S3 for web UI | Tier 2 API |
```

Use `O1-O5` prefix to distinguish from autoresearch's numeric inserts.

- [ ] **Step 3: Commit**

```bash
git add issues/3-serverless-migration/RESEARCH.md
git commit -m "research(serverless-migration): extract openclaw architecture principles (#3)"
```

---

## Stage B — Skill Scaffold

Goal: Create directory structure + empty frontmatter-only files so integrity tests can run incrementally as we fill content.

### Task B1: Create skill directory + SKILL.md stub

**Files:**
- Create: `plugins/workflow/skills/serverless-migration-advisor/SKILL.md`

- [ ] **Step 1: Verify parent directory**

Run:
```bash
ls plugins/workflow/skills/
```
Expected: `git-workflow  intent-engineering  tidd` (no `serverless-migration-advisor` yet).

- [ ] **Step 2: Write SKILL.md stub**

Write to `plugins/workflow/skills/serverless-migration-advisor/SKILL.md`:

```markdown
---
name: serverless-migration-advisor
description: AWS always-on 아키텍처(EC2/ALB/ECS/RDS)를 서버리스+Spot 패턴으로 이행할 때 사용. 워크로드 분류, 트레이드오프 평가, 단계별 이행 계획 생성. 구현 how-to는 sagemaker-spot-training 등 후속 스킬로 위임. 트리거 예 - "서버리스 이행", "EC2에서 Lambda로", "Spot 이행", "serverless migration", "ALB에서 API Gateway", "비용 절감 이행".
---

# Serverless Migration Advisor

TBD — filled in Stage F.
```

- [ ] **Step 3: Run tests (expect new-skill failures until integrity is updated)**

Run:
```bash
npm test
```
Expected: tests in `skills.test.ts` may pass (only frontmatter check at this point); `integrity.test.ts` will likely fail because marketplace.json not yet updated. **Record the exact failure** — if only integrity fails, proceed to B2. If skills.test.ts fails, fix frontmatter.

### Task B2: Create 13 reference stubs

**Files:**
- Create all under `plugins/workflow/skills/serverless-migration-advisor/references/`:

- [ ] **Step 1: Create all 13 stubs in one batch**

For each of the following filenames, create the file with the stub content:

| File | Description line |
|------|-------|
| tradeoffs-compute.md | Lambda / Fargate / Batch / SageMaker / EC2 Spot 공식 트레이드오프 |
| tradeoffs-spot.md | Spot 용량·인터럽트·HUGI·billable 정의 |
| tradeoffs-data-layer.md | RDS / Aurora Serverless v2 / DynamoDB / S3 Express |
| tradeoffs-event-driven.md | EventBridge / SQS / Kinesis / Step Functions |
| serverless-lens.md | AWS Well-Architected Serverless Lens 9개 설계원칙 |
| patterns-tier1-batch.md | 배치·훈련·ETL 이행 패턴 |
| patterns-tier2-api.md | 상시형 API·웹 이행 패턴 |
| patterns-tier3-monolith.md | Strangler Fig 기반 모놀리스 분해 |
| patterns-tier3-data.md | RDS→DynamoDB, CDC 전이 |
| interview-bank.md | Phase별 AskUserQuestion 질문 뱅크 |
| case-study-autoresearch.md | Tier 1 검증 사례 — serverless-autoresearch |
| case-study-openclaw.md | Tier 2 검증 사례 — serverless-openclaw |
| source-insights.md | 번호화된 검증 인사이트 (Insight #N 인용 대상) |

Each stub content:

```markdown
> **Snapshot date**: 2026-04-18
> **Description**: {description line from table above}

TBD — content filled in Stage C/D/E.
```

- [ ] **Step 2: Verify all 13 files exist**

Run:
```bash
ls plugins/workflow/skills/serverless-migration-advisor/references/ | wc -l
```
Expected: `13`

- [ ] **Step 3: Commit**

```bash
git add plugins/workflow/skills/serverless-migration-advisor/
git commit -m "scaffold(serverless-migration-advisor): create skill + 13 reference stubs (#3)"
```

### Task B3: Register skill in marketplace.json

**Files:**
- Modify: `.claude-plugin/marketplace.json`

- [ ] **Step 1: Read current marketplace.json**

Run:
```
Read({ file_path: "/Users/dohyunjung/Workspace/roboco-io/tools/plugins/.claude-plugin/marketplace.json" })
```

Find the `workflow` entry in `plugins[]`.

- [ ] **Step 2: Append skill path to workflow.skills array**

Edit the workflow entry's `skills` array to include:
```
"./skills/serverless-migration-advisor/SKILL.md"
```
Preserve alphabetical or existing order (match current convention).

- [ ] **Step 3: Run tests**

Run:
```bash
npm test
```
Expected: all green. If `skills.test.ts` complains about line count, the SKILL.md stub is within limits; if `integrity.test.ts` still fails, verify the exact path matches SKILL.md location.

- [ ] **Step 4: Commit**

```bash
git add .claude-plugin/marketplace.json
git commit -m "scaffold(serverless-migration-advisor): register in marketplace (#3)"
```

---

## Stage C — Authoring `tradeoffs-*.md` (5 files)

Each task in this stage has the same shape: write the file from RESEARCH.md source, then run tests, then commit. Keep each file ≤300 lines.

### Task C1: tradeoffs-compute.md

**Files:**
- Modify: `plugins/workflow/skills/serverless-migration-advisor/references/tradeoffs-compute.md`

- [ ] **Step 1: Author content**

Structure:
```markdown
> Snapshot date: 2026-04-18

# Compute Service Tradeoffs

## AWS Lambda
- Quota table (copy from RESEARCH §2.1 verbatim)
- Tradeoff implications (bullet list, 5-7 items)
- When to choose / avoid (table)
- Cite: [AWS Docs — Lambda quotas](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html)

## SageMaker Managed Spot Training
- Quota + formula (RESEARCH §3)
- State transitions table
- Cite: [AWS Docs — SageMaker Managed Spot Training](…)

## AWS Fargate + Fargate Spot
## Amazon EC2 Spot
## AWS Batch (with Spot)
```

Every quantitative claim MUST have `[AWS Docs]` inline citation.
Every pattern claim from case studies MUST have `[Insight #N]` or `[Case: autoresearch/openclaw]` citation.

- [ ] **Step 2: Run tests**

```bash
npm test
```
Expected: green.

- [ ] **Step 3: Commit**

```bash
git add plugins/workflow/skills/serverless-migration-advisor/references/tradeoffs-compute.md
git commit -m "docs(serverless-migration-advisor): tradeoffs-compute from AWS Docs + cases (#3)"
```

### Task C2: tradeoffs-spot.md

**Files:**
- Modify: `references/tradeoffs-spot.md`

- [ ] **Step 1: Author content**

Sections:
1. **Placement scores** — `aws ec2 get-spot-placement-scores` command + interpretation table (1-10 scoring meaning).
2. **Interruption behaviors** — `terminate` / `stop` / `hibernate` comparison.
3. **Interruption signals** — EventBridge event + IMDSv2 metadata example curl.
4. **HUGI principle** — billable vs wall-clock definition, cite SageMaker formula.
5. **Do / Don't** — e.g., "Don't set maximum price; it increases interruption rate." [AWS Docs — Spot interruptions §Price]
6. **Testing** — AWS FIS tutorial link.

- [ ] **Step 2: Run tests; Commit**

```bash
npm test && git add references/tradeoffs-spot.md && git commit -m "docs(serverless-migration-advisor): tradeoffs-spot with AWS FIS testing guide (#3)"
```

### Task C3: tradeoffs-data-layer.md

**Files:**
- Modify: `references/tradeoffs-data-layer.md`

- [ ] **Step 1: Author content**

Sections:
1. **RDS vs Aurora Serverless v2** — ACU range, scaling, cold-start, minimum cost floor.
2. **DynamoDB** — On-Demand vs Provisioned, consistency model, single-table tradeoff.
3. **S3 Standard vs S3 Express One Zone** — latency claim, AZ scope, pricing, directory bucket naming.
4. **Migration patterns preview** (pointer to patterns-tier3-data.md).

Each subsection cites the RESEARCH.md §14-16 facts.

- [ ] **Step 2: Run tests; Commit**

```bash
npm test && git add references/tradeoffs-data-layer.md && git commit -m "docs(serverless-migration-advisor): tradeoffs-data-layer (#3)"
```

### Task C4: tradeoffs-event-driven.md

**Files:**
- Modify: `references/tradeoffs-event-driven.md`

- [ ] **Step 1: Author content**

Sections:
1. **EventBridge** — routing, filtering, schema registry, usage cost.
2. **SQS** — FIFO vs Standard, long polling, DLQ, visibility timeout.
3. **Kinesis** — sharding, ordering, data retention.
4. **Step Functions Standard vs Express** — max duration (1 year vs 5 min), semantics (exactly-once vs at-least-once), pricing, use cases.
5. **Decision matrix** — when to choose each.

- [ ] **Step 2: Run tests; Commit**

```bash
npm test && git add references/tradeoffs-event-driven.md && git commit -m "docs(serverless-migration-advisor): tradeoffs-event-driven (#3)"
```

### Task C5: serverless-lens.md

**Files:**
- Modify: `references/serverless-lens.md`

- [ ] **Step 1: Author content**

Structure:
```markdown
> Snapshot date: 2026-04-18
> Lens publication: 2022-07-14

# AWS Well-Architected Serverless Applications Lens

## 9 Design Principles (verbatim titles)

| # | Principle | Summary | 본 스킬 활용처 |
|---|-----------|---------|---------------|
(fill from RESEARCH §12)

## 5 Pillars — Serverless-Specific Best Practices
(brief 1-line each with link)

## How This Skill Uses the Lens
- Phase 4 매핑에서 각 타겟 서비스 추천 근거로 원칙 N 인용
- Report의 Tradeoff Dossier에 리스크별 해당 원칙 표기
```

- [ ] **Step 2: Run tests; Commit**

```bash
npm test && git add references/serverless-lens.md && git commit -m "docs(serverless-migration-advisor): serverless-lens 9 principles mapping (#3)"
```

---

## Stage D — Authoring `patterns-*.md` (4 files)

### Task D1: patterns-tier1-batch.md

**Files:**
- Modify: `references/patterns-tier1-batch.md`

- [ ] **Step 1: Author content**

Three patterns, each with a standard template:
1. **EC2 long-running → SageMaker Managed Spot**
2. **EMR → AWS Batch (SPOT_CAPACITY_OPTIMIZED)**
3. **Cron on EC2 → EventBridge Scheduler + Lambda or Batch**

Template per pattern:
```markdown
### Pattern N.M: {Before} → {After}

**Applicable when:**
- …

**Before (AS-IS):**
```text
(ASCII diagram)
```

**After (TO-BE):**
```text
(ASCII diagram)
```

**Key changes:**
- …

**Tradeoffs surfaced:**
- …

**Cost range (from case study):**
- {range} [Case: autoresearch]

**Migration checklist skeleton:**
- [ ] Stage 0: …
- [ ] Stage 1: …
- [ ] Stage 2: …
- [ ] Stage 3: …

**Delegate to:** `sagemaker-spot-training` / `aws-batch-workflow` (future)

**Citations:**
- [AWS Docs — …]
- [Insight #N]
```

- [ ] **Step 2: Run tests; Commit**

```bash
npm test && git add references/patterns-tier1-batch.md && git commit -m "docs(serverless-migration-advisor): patterns-tier1-batch (#3)"
```

### Task D2: patterns-tier2-api.md

**Files:**
- Modify: `references/patterns-tier2-api.md`

- [ ] **Step 1: Author content**

Patterns:
1. **ALB + EC2 → API Gateway + Lambda** (cite openclaw O2)
2. **ECS 상시 서비스 → Fargate + Fargate Spot 혼합** (cite openclaw O1)
3. **WebSocket 상시 → API Gateway WebSocket + Lambda**
4. **Java monolith on EC2 → Lambda + SnapStart**

Same template as D1.

- [ ] **Step 2: Run tests; Commit**

```bash
npm test && git add references/patterns-tier2-api.md && git commit -m "docs(serverless-migration-advisor): patterns-tier2-api (#3)"
```

### Task D3: patterns-tier3-monolith.md

**Files:**
- Modify: `references/patterns-tier3-monolith.md`

- [ ] **Step 1: Author content**

Must include a prominent warning at top:

```markdown
> **⚠️ Tier 3 범위 경고**: 두 검증 사례(autoresearch, openclaw)는 Tier 3 이행을 직접 검증하지 않았습니다. 본 문서는 AWS 공식 패턴 링크 + 원칙 수준 가이드만 제공합니다. 대규모 프로젝트 전 파일럿 필수.
```

Patterns:
1. **Strangler Fig Application** (cite AWS prescriptive guidance)
2. **Branch by Abstraction**
3. **Database-per-service 이전**

Each pattern: principle + AWS docs link + "do / don't" list. No before/after diagrams (not validated).

- [ ] **Step 2: Run tests; Commit**

```bash
npm test && git add references/patterns-tier3-monolith.md && git commit -m "docs(serverless-migration-advisor): patterns-tier3-monolith with validation warning (#3)"
```

### Task D4: patterns-tier3-data.md

**Files:**
- Modify: `references/patterns-tier3-data.md`

- [ ] **Step 1: Author content**

Same Tier 3 warning at top.

Patterns:
1. **RDS → Aurora Serverless v2** (동일 엔진 유지, 최저 위험)
2. **RDS → DynamoDB** (access pattern re-design 필요, CDC 기반 전이)
3. **Add S3 Express One Zone** for high-IO batch reads

Cite AWS DMS (Database Migration Service) where applicable.

- [ ] **Step 2: Run tests; Commit**

```bash
npm test && git add references/patterns-tier3-data.md && git commit -m "docs(serverless-migration-advisor): patterns-tier3-data (#3)"
```

---

## Stage E — Case Studies + Insights + Interview Bank

### Task E1: case-study-autoresearch.md

**Files:**
- Modify: `references/case-study-autoresearch.md`

- [ ] **Step 1: Author content**

Structure:
```markdown
> Snapshot date: 2026-04-18
> Source: github.com/roboco-io/serverless-autoresearch @ commit 5435b37
> Local path: /Users/dohyunjung/Workspace/roboco-io/research/serverless-autoresearch/

# Case Study — serverless-autoresearch (Tier 1)

## Headline
- 48 Spot 실험 / 총비용 $3.94
- H100 Spot 229초 / $0.16 (상용 대비 $7-24/8h)
- Karpathy autoresearch 재현: val_bpb 0.9951 (원본 ~0.998)

## Architecture
(ASCII diagram: 사용자 → batch_launcher → N개 SageMaker Spot jobs → result_collector)

## Quotable Statements (for skill output)
- "이 워크로드는 상용 대비 20-100× 저렴하게 재현 가능 — [Case: autoresearch]"
- "Spot 인터럽트율 H100 ~5% — [Case: autoresearch Insight #N]"

## Applicable workloads
- 배치 훈련, HPO, 여러 config 병렬 비교.

## Not applicable
- 단일 긴 연속 훈련 (체크포인트 오버헤드), 초저지연 추론.

## Cross-references
- patterns-tier1-batch.md §1.1
- source-insights.md #1-15
```

- [ ] **Step 2: Run tests; Commit**

```bash
npm test && git add references/case-study-autoresearch.md && git commit -m "docs(serverless-migration-advisor): case-study-autoresearch (#3)"
```

### Task E2: case-study-openclaw.md

**Files:**
- Modify: `references/case-study-openclaw.md`

- [ ] **Step 1: Author content**

Structure parallels E1:
```markdown
# Case Study — serverless-openclaw (Tier 2)

## Headline
- 월 $1-2 (Free Tier 시 $0.23)
- Lambda Container 콜드 스타트 1.35s
- API Gateway 채택으로 ALB 고정비 $18-25/월 제거
- ECS Fargate Spot fallback으로 컴퓨트 70% 절감

## Architecture
(ASCII: API Gateway → Lambda Container (primary) ↔ S3 session; fallback → ECS Fargate Spot; EventBridge scheduled pre-warming)

## Quotable Statements
## Applicable / Not applicable
## Cross-references (patterns-tier2-api.md O1-O5)
```

- [ ] **Step 2: Run tests; Commit**

```bash
npm test && git add references/case-study-openclaw.md && git commit -m "docs(serverless-migration-advisor): case-study-openclaw (#3)"
```

### Task E3: source-insights.md

**Files:**
- Modify: `references/source-insights.md`

- [ ] **Step 1: Author content**

```markdown
> Snapshot date: 2026-04-18

# Source Project Insights (Numbered — stable references)

## From serverless-autoresearch (Insight #1-#15)

### Insight #1 — Spot Capacity Varies Dramatically by Region
… (one paragraph from autoresearch/docs/insights.md §1)
**Tier:** 1
**Cited by:** tradeoffs-spot.md, patterns-tier1-batch.md §1.1

### Insight #2 — …
(continue for all 15)

## From serverless-openclaw (Insight #O1-#O5)

### Insight #O1 — Dual Compute (Lambda primary + Fargate Spot fallback)
…
**Tier:** 2
**Cited by:** patterns-tier2-api.md §1.2
```

**Numbering rule:** autoresearch insights are numeric `#1-#15` (stable). openclaw principles are prefixed `#O1-#O5`. Future additions only extend (never renumber).

- [ ] **Step 2: Run tests; Commit**

```bash
npm test && git add references/source-insights.md && git commit -m "docs(serverless-migration-advisor): numbered source-insights reference (#3)"
```

### Task E4: interview-bank.md

**Files:**
- Modify: `references/interview-bank.md`

- [ ] **Step 1: Author content**

Structure:
```markdown
> Snapshot date: 2026-04-18

# Interview Bank — AskUserQuestion Templates

## Phase 1: Classification (always asked)

### Q1 — Workload type
```json
{
  "question": "현재 워크로드의 주 타입을 선택해주세요.",
  "header": "워크로드",
  "multiSelect": false,
  "options": [
    { "label": "배치/훈련", "description": "..." },
    ...
  ]
}
```
(Provide full JSON for Q1-Q4 of Phase 1)

## Phase 3 (branches by Phase 1)

### Branch: batch/training
- Q_B1: Spot 인터럽트 허용도
- Q_B2: 작업 최대 허용 wall-clock
- Q_B3: 체크포인트 지원 가능 여부

### Branch: always-on API
- Q_A1: 콜드 스타트 p99 허용
- Q_A2: 지속 연결 요구 (WebSocket / SSE)
- Q_A3: 트래픽 패턴 (상시 / 버스트 / 주기)

### Branch: ETL
- Q_E1: 데이터 볼륨 / 실행 당
- Q_E2: 작업 단위 지속 시간
- Q_E3: 상태 저장소 (S3 / RDS / DynamoDB)

### Branch: event-driven
- Q_V1: 이벤트 소스
- Q_V2: 처리 순서 보장 필요?
- Q_V3: 중복 허용?

### Branch: monolith (Tier 3)
- 먼저 경고: "이 스킬은 Tier 3를 원칙 수준으로만 안내합니다."
- Q_M1: 서비스 경계 식별 단계 (초기/중기/후기)
- Q_M2: 다운타임 허용 윈도우
- Q_M3: 데이터 일관성 요구

## Common follow-ups (asked for every tier)
- Q_C1: 월 목표 비용
- Q_C2: 규정 준수 (PCI/HIPAA/GDPR/SOC2/없음)
- Q_C3: RTO / RPO
```

Provide full JSON for at least Q1 (Phase 1) and one Q per branch as a template. Remaining questions show minimal schema.

- [ ] **Step 2: Run tests; Commit**

```bash
npm test && git add references/interview-bank.md && git commit -m "docs(serverless-migration-advisor): interview-bank with 5 branches (#3)"
```

---

## Stage F — Write SKILL.md Body

### Task F1: Full SKILL.md

**Files:**
- Modify: `plugins/workflow/skills/serverless-migration-advisor/SKILL.md`

- [ ] **Step 1: Draft SKILL.md (≤500 lines)**

Structure (preserve frontmatter from Stage B):

```markdown
---
name: serverless-migration-advisor
description: ... (from Task B1)
---

# Serverless Migration Advisor

**Role:** 기존 AWS 워크로드를 서버리스+Spot 패턴으로 이행할 때 분류·트레이드오프 평가·단계별 계획을 생성하는 업스트림 어드바이저. 구현 how-to는 후속 스킬로 위임.

**이 스킬이 아닌 것:**
- aws-well-architected는 기존 아키텍처의 Pillar 준수 리뷰. 본 스킬은 **이행**에 집중.
- 실시간 AWS 요금 계산기 아님. 실험 기반 범위만 인용.
- Terraform 생성기 아님. 스니펫 + 체크리스트까지.

## 언제 사용하나
트리거 키워드: "서버리스 이행", "EC2에서 Lambda로", "Spot 이행", "ALB에서 API Gateway", "월 비용 절감 이행", "serverless migration", "batch on Spot".

## 실행 순서 (5 Phase)

### Phase 1 — 워크로드 분류 인터뷰
references/interview-bank.md의 Phase 1 JSON 4개 질문을 AskUserQuestion으로 순차 호출.

### Phase 2 — IaC 스캔 (선택)
사용자가 IaC 경로(Terraform/CDK/CFN)를 제공하면 정적 스캔. 파일 없으면 스킵.
(첫 버전: 정규식으로 `resource "aws_instance"`, `aws_rds_cluster`, `aws_ecs_service` 등 추출)

### Phase 3 — 제약·리스크 인터뷰
Phase 1 응답 기반 분기 (interview-bank.md §Phase 3).

### Phase 4 — 타겟 아키텍처 매핑
(매핑 테이블 인라인 — SPEC §3 Phase 4와 동일)

각 매핑 추천 시:
1. references/patterns-tier{N}-*.md에서 해당 패턴 로드.
2. references/tradeoffs-*.md에서 리스크·제약 확인.
3. references/case-study-*.md에서 수치 범위 인용.

### Phase 5 — 리포트 생성
docs/serverless-migration/YYYY-MM-DD-{topic}.md 저장.
(리포트 템플릿 인라인 — SPEC §5 스키마)

## 인용 라벨 규칙 (의무)
- `[AWS Docs]` — AWS 공식문서 출처 (URL 동반)
- `[Insight #N]` — source-insights.md 항목 (번호 stable)
- `[Case: autoresearch|openclaw]` — 검증 사례 근거

모든 정량 주장·추천 근거는 위 세 라벨 중 최소 하나를 동반해야 함.

## Delegation
| 타겟 서비스 | 위임 스킬 |
|------------|----------|
| SageMaker Managed Spot Training | `sagemaker-spot-training` (존재) |
| Lambda / API Gateway | 없음 — AWS Docs 링크 제공 |
| AWS Batch | 없음 — AWS Docs 링크 제공 |
| ECS Fargate + Fargate Spot | 없음 — AWS Docs 링크 제공 |

## Tier 3 주의
Tier 3 (모놀리스 분해 / DB 교체)는 **검증 사례 없음**.
patterns-tier3-*.md 상단 경고를 리포트에도 복제.

## 설정 파일 (선택)
프로젝트 루트에 `.serverless-migration.yaml` 존재 시 기본값 사용:
```yaml
default_region: us-west-2
report_dir: docs/serverless-migration/
language: ko
```

## 오류 모드 (의무 노출 — SPEC §11)
- CUDA / FA3 호환성 [Insight #4, #13]
- Spot 쿼터 지연 (H100: days) [Insight from spot-capacity-guide]
- Cold start 신규 리스크 [AWS Docs — Lambda quotas]
- Fargate Spot 단일 태스크 가용성 위험 [AWS Docs — Fargate capacity providers]

## References (Progressive Disclosure)
(13 files listed with one-line each)
```

**Verify line count:**
```bash
wc -l plugins/workflow/skills/serverless-migration-advisor/SKILL.md
```
Expected: ≤500.

- [ ] **Step 2: Run tests**

```bash
npm test
```
Expected: green.

- [ ] **Step 3: Commit**

```bash
git add plugins/workflow/skills/serverless-migration-advisor/SKILL.md
git commit -m "feat(serverless-migration-advisor): write 5-Phase SKILL.md body (#3)"
```

---

## Stage G — Integration

### Task G1: README.md update

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Locate Workflow skills section**

Run:
```
Grep({ pattern: "### Workflow", path: "README.md", output_mode: "content", -n: true })
```

- [ ] **Step 2: Add skill row**

Append (or insert alphabetically) in the Workflow table:

```markdown
| [serverless-migration-advisor](plugins/workflow/skills/serverless-migration-advisor) | AWS always-on 아키텍처를 서버리스+Spot 패턴으로 이행하는 업스트림 어드바이저. 트레이드오프·리스크·단계별 계획 생성 후 구현 스킬로 위임. |
```

- [ ] **Step 3: Run tests; Commit**

```bash
npm test && git add README.md && git commit -m "docs: list serverless-migration-advisor in README (#3)"
```

### Task G2: CHANGELOG.md update

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add Unreleased entry (or new version section)**

Insert at top of Unreleased section:

```markdown
### Added
- `serverless-migration-advisor` 스킬 추가: AWS always-on 아키텍처를 서버리스+Spot 패턴으로 이행하기 위한 업스트림 어드바이저. 5-Phase 인터뷰 → 타겟 아키텍처 매핑 → 단계별 체크리스트 리포트. AWS Docs + serverless-autoresearch + serverless-openclaw 검증 사례 기반. (#3)
```

- [ ] **Step 2: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): note serverless-migration-advisor skill (#3)"
```

### Task G3: Update issues/3-serverless-migration/PLAN.md status

**Files:**
- Modify: `issues/3-serverless-migration/PLAN.md`

- [ ] **Step 1: Check implementation checkboxes (§4)**

Mark all 산출물 checkboxes `[x]`.

- [ ] **Step 2: Commit**

```bash
git add issues/3-serverless-migration/PLAN.md
git commit -m "docs(issues/3): check off PLAN implementation deliverables (#3)"
```

---

## Stage H — Verification

### Task H1: Full test suite

- [ ] **Step 1: Run full test suite**

```bash
npm test
```
Expected: all tests pass.

- [ ] **Step 2: Check skill line count**

```bash
wc -l plugins/workflow/skills/serverless-migration-advisor/SKILL.md
```
Expected: ≤500.

- [ ] **Step 3: Check each reference line count (sanity)**

```bash
wc -l plugins/workflow/skills/serverless-migration-advisor/references/*.md
```
Expected: each ≤500 (no hard limit but keeps progressive disclosure working).

### Task H2: Scenario rehearsal (manual)

These run inside Claude Code itself — not automated. For each scenario below, invoke the skill mentally (or actually, if plugin is installed locally) and verify outputs match expectations.

- [ ] **Scenario 1 (Tier 1):** "나는 EC2 H100에서 매일 8시간 배치 훈련을 돌리고 월 $1,800을 지출한다. 서버리스로 이행 가능한가?"
  - Expected Phase 1 classification: `배치/훈련` + `상시 API 아님`.
  - Expected Phase 4 target: SageMaker Managed Spot Training.
  - Expected report cites: [Case: autoresearch], Insight #1, #5, AWS Docs (SageMaker Managed Spot + Spot interruptions).
  - Expected delegation: "sagemaker-spot-training 스킬로 이어 진행".

- [ ] **Scenario 2 (Tier 2):** "ALB + EC2 Auto Scaling으로 트래픽 변동이 큰 REST API를 운영 중. 월 $800."
  - Expected Phase 1: `상시 API`.
  - Expected Phase 4 target: Lambda + API Gateway (primary), Fargate + Fargate Spot (fallback).
  - Expected report cites: [Case: openclaw] O1-O2, AWS Docs (Lambda quotas + Fargate capacity providers).
  - Expected delegation: AWS Docs 링크 (전용 스킬 없음 명시).

- [ ] **Scenario 3 (Tier 3):** "Spring Boot 모놀리스 + RDS PostgreSQL. 서버리스로 이행 가능한가?"
  - Expected Phase 1: `모놀리스`.
  - Expected response: Tier 3 경고 + Strangler Fig 패턴 + pilot 필수 경고.
  - Expected target: 먼저 분해, 이후 단계별 이행.
  - Expected no suggestion to jump directly to Lambda.

Document any deviations in `issues/3-serverless-migration/VERIFICATION.md`.

### Task H3: PR preparation

- [ ] **Step 1: Branch / commit state**

```bash
git log --oneline main..HEAD
```
Expected: clean history of Stage A-G commits.

- [ ] **Step 2: Prepare PR description**

Draft the PR with:
- Link to Issue #3
- Link to SPEC.md, PLAN.md, TASKS.md, RESEARCH.md
- Scenario H2 results
- Test output snippet (`npm test` green)

- [ ] **Step 3: (User decision) Create PR or keep as local draft**

User must explicitly approve PR creation. Do not push without confirmation.

---

## Self-Review (run before marking plan complete)

Check each spec requirement against a task:

| SPEC section | Implemented by task |
|--------------|---------------------|
| §2.1 Directory layout | B1, B2 |
| §3 Phase 1-5 flow | F1 |
| §4.1 Lambda tradeoffs | C1 |
| §4.2 SageMaker Managed Spot | C1 |
| §4.3 Fargate Spot | C1, C2 |
| §4.4 EC2 Spot | C2 |
| §4.5 AWS Batch | C1 |
| §4.6 Serverless Lens | C5 |
| §5 Report schema | F1 (inline template) |
| §6 Interview system | E4, F1 |
| §7 Delegation | F1, D1-D2 |
| §8 Case study citation rules | E1, E2, E3 |
| §9 Tier 3 treatment | D3, D4, F1 |
| §10 Deliverables list | all Stage B-G |
| §11 Non-goals | F1 (explicit section) |
| §12 Success criteria (6 bullets) | H2 scenarios |

**Placeholder scan:** this plan contains no `TBD` outside of Task B1/B2 stubs that are explicitly filled in later stages. Every step with code shows the code. Every command shows expected output.

**Type consistency:** N/A (no code).

**Naming consistency:**
- `serverless-migration-advisor` (skill name) — used verbatim everywhere.
- `[AWS Docs]` / `[Insight #N]` / `[Case: …]` — citation labels consistent across all tasks.
- `references/` paths use exact filenames from §File Structure.

---

## Execution Handoff

Plan saved to `issues/3-serverless-migration/TASKS.md`. Two execution options:

**1. Subagent-Driven (recommended)** — dispatch a fresh subagent per Stage (A/B/C/D/E/F/G/H), review between stages. Best for quality gates.

**2. Inline Execution** — execute tasks in this session with checkpoints after each Stage. Faster but less review surface.

Awaiting user decision.
