# Issue #3: Serverless Migration Skill — Handoff Document

> **To the agent picking this up:** this is a handoff from the
> `serverless-autoresearch` project. Read this end-to-end before writing any
> code. The source repository (see §3) contains the lessons that should power
> this skill — extract, don't reinvent. Write `SPEC.md` and `PLAN.md` in this
> directory once you've decided scope and architecture.

## 1. Goal

Build a Claude Code skill (or skill family) that helps users **migrate an
existing, always-on architecture to a serverless + Spot pattern on AWS**, with
particular emphasis on the lessons proven out in the source project.

The skill should let a user describe their current workload (batch training,
ETL job, long-running service, ML inference, etc.) and receive:

1. A feasibility assessment (is this workload a good serverless+Spot candidate?)
2. A concrete migration plan (target AWS services, cost/time estimate, risks)
3. Drop-in IaC / code patterns where applicable
4. Pitfalls to avoid, drawn from real experience

## 2. Why this skill

The source project (`serverless-autoresearch`) demonstrated that a workload
most people assume needs a dedicated H100 for 8 hours can actually run on
Spot for **229 seconds at $0.16**, matching the reference result. Same
technique transfers to many batch-style workloads. The lessons are concrete
and hard-won; putting them behind a skill lets other teams apply them without
re-learning the same failures.

## 3. Source project — what to mine

Repository: `/Users/dohyunjung/Workspace/roboco-io/research/serverless-autoresearch/`
(GitHub: `roboco-io/serverless-autoresearch`, main branch)

### 3.1 Primary sources (read these first)

| Path | What it contains | Why it matters |
|------|-----------------|----------------|
| `docs/insights.md` | 15 numbered lessons from 48 real Spot experiments | **Core knowledge base**. Every insight is battle-tested. Several directly contradict intuition (e.g. #3/#12 vs #13). |
| `docs/comparison-report.md` | Sequential-dedicated vs parallel-Spot architecture analysis | Migration narrative: before/after |
| `docs/spot-capacity-guide.md` | How to find Spot capacity by region, quota flow | First-mile problem for every Spot migration |
| `docs/gpu-cost-analysis.md` | P5/P6 pricing, per-experiment cost math | Concrete cost templates |
| `experiments/003-h100-comparison/results-summary.md` | Full multi-phase experiment report | End-to-end worked example |
| `experiments/001-baseline-l40s/`, `002-optimization-l40s/` | Earlier experiment reports | Shows the incremental path — useful for the skill's suggested migration stages |
| `README.md` | Project summary, 48-experiment program, $3.94 total | Headline numbers for the skill's "what's possible" pitch |

### 3.2 Code patterns (reusable snippets)

| Path | Pattern demonstrated |
|------|---------------------|
| `src/pipeline/batch_launcher.py` | Submitting N parallel SageMaker Spot jobs with `use_spot_instances=True`, `max_wait`, retry-safe structure |
| `src/pipeline/result_collector.py` | Polling multiple async SageMaker jobs, extracting metrics from CloudWatch logs |
| `src/pipeline/orchestrator.py` | Generation-loop coordination across parallel Spot jobs |
| `src/sagemaker/entry_point.py`, `train_wrapper.py` | Container entry point that works under SageMaker's S3 input-channel convention |
| `infrastructure/setup_iam.sh` | Minimal IAM role for SageMaker training (execution + S3 access) |
| `infrastructure/requirements-train.txt` | Pinned deps compatible with SageMaker PyTorch DLC 2.8.0 |
| `config.yaml.example` | Config template: profile, region, instance type, Spot flags, time budget |
| `Makefile` | `dry-run`, `run-single`, `run`, `cost` commands — the UX template the skill should replicate |

### 3.3 Diagrams (for reference / inspiration, don't copy verbatim)

- `docs/architecture.svg` — system architecture
- `docs/comparison-diagrams.svg` — sequential vs parallel visual

## 4. Core knowledge to surface

Distilled from the source project's `docs/insights.md`, the skill must teach
or apply at minimum these principles:

### 4.1 Spot-specific operational knowledge
- **Region/AZ matters more than instance size** — Spot placement scores
  vary 1–9 across regions for the same SKU. Always check
  `aws ec2 get-spot-placement-scores` before committing to a region.
- **Larger instances can be cheaper on Spot** — less demand. Don't assume
  smaller = cheaper.
- **Quota is the first-mile problem** — g-family auto-approves in minutes,
  p-family (H100, B200) needs days of lead time.
- **Spot interrupt risk is workload-length-dependent** — under ~30 min,
  Spot is almost free. Beyond that, interrupt-handling matters.
- **Billable ≠ wall clock** — SageMaker Spot only bills training time,
  not Spot wait, not startup. This is the real cost model.

### 4.2 Cost & time patterns
- **HUGI (Hurry Up and Get Idle)** — only pay when compute is active;
  let the platform release the instance the instant the job ends. Always-on
  servers lose to HUGI on any bursty workload.
- **Parallelism cuts wall clock, not cost** — N-way parallel Spot is the
  same billable time as sequential, at 1/N the wall clock.
- **Startup overhead matters at short durations** — SageMaker startup is
  ~3 min. For 5-min jobs, that's 60% overhead. Either amortize (batch more
  work per job) or choose a platform with lower cold-start (Lambda, Fargate
  Spot, Batch).

### 4.3 Migration-specific pitfalls (from experience)
- **Hyperparameters and batch size interact across hardware** (insight
  #13). When migrating a workload, don't assume "same config" — LR-like
  settings that depended on the old hardware's memory limits may need to
  be re-examined after the move.
- **Cheap-GPU-evolved configs often transfer to expensive GPUs** (insight
  #14). For iteration-heavy workloads, run exploration on cheap Spot, then
  promote the winner. Don't start on the expensive tier.
- **Transient CUDA / Spot errors happen** at ~5% rate on H100 Spot. Any
  migration plan needs automatic retry baked in; one failure out of 20 is
  normal, not a signal to abandon Spot.
- **Kernel/accelerator support varies by GPU** (FA3 sm_90 only, etc.). A
  serverless migration across GPU types needs a fallback path.

### 4.4 The concrete achievement to cite

The source project reproduced Karpathy's upstream autoresearch result
(val_bpb ~0.998) to **val_bpb = 0.9951 on a single 229-second H100 Spot
run costing $0.16**, versus the upstream's estimated **$7–24 over 8 hours**.
Total program: 48 experiments across L40S + H100 for **$3.94**. These are
the numbers the skill should be able to quote as the "what's actually
possible" anchor.

## 5. Suggested scope (the agent decides)

The ask — "help migrate any architecture to serverless" — is broad. A
plausible scoping, for the agent to accept, refine, or reject:

**Tier 1 (must-have):** batch/training/ETL workloads → Spot + S3 + managed
service (SageMaker Training / AWS Batch / Fargate Spot). This is where the
source project's experience is deepest.

**Tier 2 (extend if time permits):** always-on API → Lambda / API Gateway
or ECS Fargate. Source project doesn't cover this directly but HUGI
principles apply.

**Tier 3 (probably out of scope):** full legacy monolith decomposition,
data layer migration (RDS → DynamoDB), event-driven re-architecture.
These are bigger than a single skill.

Reasonable options for skill structure:

- **Option A — single skill** `serverless-migration-advisor`. One SKILL.md
  with workload-type branches internally. Simpler to maintain, harder to
  load selectively.
- **Option B — orchestrator + sub-skills**, like the `aws-well-architected`
  family (see `issues/2-aws-well-architected-review/SPEC.md`). Main skill
  routes to `serverless-migration-batch`, `serverless-migration-api`, etc.
  Matches the existing plugin repo pattern.
- **Option C — complement an existing skill**. The source project's
  CLAUDE.md mentions a `sagemaker-spot-training` skill at
  `github.com/roboco-io/claude-skills`. If that skill already covers the
  training-workload case, this new skill should focus on migration framing
  (before-state analysis, service selection, cost/risk call-out) rather
  than reimplement SageMaker-specific how-to.

**Recommendation:** investigate Option C first. If the existing skill is
hands-on-how-to, this new skill should be the upstream migration advisor
that eventually *delegates* to it. Don't duplicate.

Category placement in the plugin repo: either `development/` or
`workflow/`. `workflow/` fits "migration process" framing better.

## 6. Non-goals

- **Not a cost calculator** — skill should cite cost *patterns and ranges*
  from real experiments, not compute live AWS prices.
- **Not a Terraform generator** — emit *snippets and structural guidance*,
  not a full IaC suite.
- **Not a multi-cloud story** — AWS-only, matching source project scope.
- **Not silent about limits** — must surface the source project's actual
  failure modes (CUDA errors, quota delays, FA3 compatibility, etc.),
  not only the wins.

## 7. Success criteria

A user arrives with "I have a nightly batch job running on an EC2 H100 that
costs $N/month and I want it cheaper." The skill should, within one
interaction:

1. Classify the workload (batch-training / batch-ETL / inference / long-running)
2. Identify the target serverless pattern (SageMaker Spot / Batch / Fargate Spot / Lambda)
3. Estimate cost savings range (citing source-project precedents where relevant)
4. Flag top 3 risks specific to that workload type (Spot interrupts, cold start, quota, etc.)
5. Produce a staged migration plan: validation-on-cheap-Spot → production-on-target
6. Cite the source project's insights (numbered) where the advice originates — traceable, not black-box.

A secondary marker: if the user has an IaC file (Terraform, CDK, CloudFormation),
the skill can read it and produce a *diff-style* migration sketch rather than
starting from a blank page.

## 8. Implementation constraints

Follow the plugin repo's conventions (`plugins/tools/plugins/CLAUDE.md`):

- YAML frontmatter + Markdown in every SKILL.md
- Progressive disclosure via `references/` subdirectory
- Update `.claude-plugin/marketplace.json` `plugins` array when adding the plugin
- Keep SKILL.md under ~500 lines; offload detail to `references/`
- Add the plugin under `plugins/{category}/.claude-plugin/plugin.json`

## 9. Deliverables (for the agent)

In this directory (`issues/3-serverless-migration/`):

1. **`SPEC.md`** — your refined scope, architecture, skill structure,
   interview/output contracts. Follow the style of `issues/2-aws-well-architected-review/SPEC.md`.
2. **`PLAN.md`** — implementation steps, ordered, with rough effort estimates.
3. (optional) **`RESEARCH.md`** — your investigation of the existing
   `sagemaker-spot-training` skill (referenced in §5 Option C) and how
   this new skill should complement or supersede it.

Then proceed with implementation in `plugins/{chosen-category}/skills/...`.

## 10. Open questions for the agent to resolve

- Does `github.com/roboco-io/claude-skills` have a live `sagemaker-spot-training`
  skill? If yes, what's its exact scope? (Drives §5 Option A vs C.)
- Should the skill interview the user (like `aws-well-architected`) or work
  from a single declarative input (paste your Terraform)? Probably both.
- How to represent "staged migration" — as a checklist skill output? A
  generated issue tree? A Terraform-diff format?
- Where do the numbered source-project insights live in the skill? Inline
  citations in output, or an appended `references/source-insights.md`?

---

*Handoff prepared 2026-04-18 from serverless-autoresearch commit `5435b37`.*
*Source project contact: `/Users/dohyunjung/Workspace/roboco-io/research/serverless-autoresearch/`.*
