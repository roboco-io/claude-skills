# Serverless Autoresearch — Key Insights

> Lessons learned from running autonomous ML experiments on SageMaker Spot Training.

## 1. Spot Capacity Varies Dramatically by Region

**Discovery:** The same instance type can have Spot placement score 1 (near-impossible) in one region and 9 (instant) in another.

| Region | g7e Score | Result |
|--------|----------|--------|
| us-west-2 | 1-2 | Stuck "Starting" 30+ min |
| us-east-1 | 9 | Allocated in ~2 min |

**Rule:** Always run `aws ec2 get-spot-placement-scores` before choosing a region. See [Spot Capacity Guide](spot-capacity-guide.md).

## 2. Larger Instances Can Be Cheaper on Spot

**Discovery:** g7e.8xlarge ($0.93/hr) was cheaper than g7e.2xlarge ($0.94-$1.82/hr) in us-west-2 because larger instances have less Spot demand.

**Rule:** Check Spot price history for all sizes — don't assume smaller = cheaper.

## 3. DEVICE_BATCH_SIZE ≠ Token Throughput

**Discovery:** Doubling DEVICE_BATCH_SIZE from 64 to 128 with the same TOTAL_BATCH_SIZE **worsened** val_bpb (1.065 → 1.081).

**Why:** With TOTAL_BATCH_SIZE fixed at 2^19, larger DEVICE_BATCH_SIZE reduces gradient accumulation steps (4 → 2) without increasing total tokens processed. It just uses more VRAM for the same work.

**Rule:** To increase throughput, increase TOTAL_BATCH_SIZE (more tokens per optimizer step), not just DEVICE_BATCH_SIZE.

## 4. Flash Attention 3 is GPU-Architecture Specific

**Discovery:** FA3 pre-compiled kernels only support Hopper (sm_90) and Ampere (sm_80/86). Ada Lovelace (sm_89, L40S) is **not supported**, causing runtime CUDA errors.

**Solution:** Explicit compute capability check + PyTorch SDPA fallback. FA2 has community wheels for sm_89.

**Impact:** SDPA gives ~20% MFU vs ~40% with FA3 — half the attention efficiency.

## 5. SageMaker Startup Overhead is Significant

**Discovery:** Each SageMaker Training Job has ~3 min startup overhead (instance allocation + container pull + data download + pip install). For 5-min training jobs, this is **60% overhead**.

**Optimization paths:**
- **Scale up:** Use multi-GPU instance, run N experiments on 1 job (amortize startup)
- **Pre-install deps:** Bake packages into Docker image instead of pip install at runtime
- **Warm pools:** SageMaker warm pools keep instances alive between jobs (but costs money)

## 6. Quota Management is a First-Class Concern

**Discovery:** GPU Spot quotas default to 0 for new instance types. g7e auto-approved within minutes; p5/p6 require manual review (CASE_OPENED, days).

**Rule:** Request quotas in multiple regions upfront. g7e tends to auto-approve; p5+ needs lead time.

## 7. SageMaker Profiler Doesn't Support All Instance Types

**Discovery:** `ml.g7e` instances throw `ValidationException: Profiler is currently not supported` at job creation.

**Fix:** Set `disable_profiler=True` in the PyTorch Estimator.

## 8. The Parallel Evolution Approach Works

**Validated:** The pipeline successfully generates candidates, submits parallel Spot jobs, collects results, and selects the best — all autonomously.

**Cost efficiency:** 4 parallel experiments for $0.066 total, results in ~10 min wall clock (excluding Spot wait time in us-west-2).

## 9. PyArrow Version Matters

**Discovery:** The SageMaker DLC has pyarrow 23.x, but the local environment may have an older version causing `Repetition level histogram size mismatch` when reading parquet files.

**Fix:** Ensure `pyarrow>=21.0.0` in requirements-train.txt.

## 10. config.yaml Should Never Be in Git

**Discovery:** config.yaml contains AWS role ARN, profile, and region — environment-specific and potentially sensitive.

**Rule:** Gitignore config.yaml, provide config.yaml.example as template.

## 11. Spot GPUs Are Valid Proxies for Large-Scale Training

**Discovery:** Research confirms that hyperparameter optimization on cheaper GPUs (L40S) transfers well to expensive GPUs (H100) for production training.

**What transfers:**
- Optimizer choices (Muon vs AdamW) — relative rankings hold across hardware
- Architecture decisions (depth, width, attention patterns) — hardware-independent
- LR schedule shapes (cosine, warmup ratios) — direction transfers, absolute values need adjustment
- Relative hyperparameter rankings — "A is better than B" conclusions are portable

**What doesn't transfer:**
- Absolute val_bpb values — depend on GPU throughput
- Optimal batch sizes — depend on VRAM (48GB vs 80GB)
- Memory-dependent optimizations — FA3 (Hopper only), FP8, etc.
- Absolute learning rate values — need per-scale tuning without muP

**Rule:** Use Spot for Phase 1 (hypothesis validation at $0.04/experiment), then apply winning architecture/optimizer choices to Phase 2 (full-scale training on H100). Use muP for direct LR transfer across scales.

**References:**
- [MLPerf BERT HPC Optimization (arXiv 2402.02447)](https://arxiv.org/pdf/2402.02447)
- [Improving HPO with Checkpointed Weights (NVIDIA 2024)](https://research.nvidia.com/publication/2024-06_improving-hyperparameter-optimization-checkpointed-model-weights)
- [muP Scaling (arXiv 2410.22854)](https://arxiv.org/html/2410.22854v3)

## 12. DEVICE_BATCH_SIZE ≠ More Training

**Discovery (Experiment #002):** Doubling DEVICE_BATCH_SIZE from 64 to 128 while keeping TOTAL_BATCH_SIZE=2^19 **worsened** val_bpb (1.065 → 1.081). It only reduced gradient accumulation steps (4 → 2) without increasing total tokens.

**Rule:** To increase throughput, increase TOTAL_BATCH_SIZE. DEVICE_BATCH_SIZE only affects VRAM usage and gradient accumulation granularity.
