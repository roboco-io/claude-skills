# GPU Instance Cost Analysis: P5 vs P6 for Autoresearch

> Comparing H100 (P5), B200 (P6-B200), and B300 (P6-B300) for single-GPU ML experiment workloads on SageMaker Spot Training.

---

## 1. GPU Performance Specifications

| GPU | Architecture | BF16 TFLOPS | VRAM | Memory BW | vs H100 |
|-----|-------------|-------------|------|-----------|---------|
| **H100** | Hopper | 990 | 80 GB | 3,350 GB/s | 1.0x |
| **B200** | Blackwell | 2,250 | 180 GB | 8,000 GB/s | **2.27x** |
| **B300** | Blackwell Ultra | ~3,375 | 288 GB | 8,000 GB/s | **~3.4x** |

Sources: [NVIDIA Data Center GPU Specs](https://intuitionlabs.ai/articles/nvidia-data-center-gpu-specs), [B200 vs H100](https://www.civo.com/blog/comparing-nvidia-b200-and-h100), [B300 vs B200](https://verda.com/blog/nvidia-b300-vs-b200-complete-gpu-comparison-to-date)

## 2. SageMaker Instance Configuration & Pricing

### Available Instances

| Instance | GPUs | GPU Type | Total VRAM |
|----------|------|----------|-----------|
| **ml.p5.4xlarge** | **1** | H100 | 80 GB |
| ml.p5.48xlarge | 8 | H100 | 640 GB |
| ml.p6-b200.48xlarge | 8 | B200 | 1,440 GB |
| ml.p6-b300.48xlarge | 8 | B300 | 2,100 GB |

**Critical note:** P6 instances are only available in 48xlarge (8 GPU) size. There is no single-GPU P6 option.

### Pricing (us-west-2, estimated)

| Instance | On-Demand/hr | Spot (~65% off) | Spot per GPU/hr |
|----------|-------------|-----------------|-----------------|
| **ml.p5.4xlarge** | $6.88 | ~$2.40 | **$2.40** |
| ml.p6-b200.48xlarge | $113.93 | ~$39.88 | $4.98 |
| ml.p6-b300.48xlarge | $142.42 | ~$49.85 | $6.23 |

Sources: [p5.4xlarge pricing](https://instances.vantage.sh/aws/ec2/p5.4xlarge), [p6-b200 pricing](https://instances.vantage.sh/aws/ec2/p6-b200.48xlarge), [EC2 Capacity Blocks Pricing](https://aws.amazon.com/ec2/capacityblocks/pricing/)

## 3. The Core Problem: P6 Has No Single-GPU Option

Autoresearch is a **single-GPU workload**. Each experiment runs `train.py` on one GPU for 5 minutes. When using a P6 instance (8 GPUs), **7 out of 8 GPUs sit completely idle**, making P6 dramatically cost-inefficient unless the pipeline is redesigned.

```
P5.4xlarge (1 GPU):
  [████ USED ████]                          → 100% utilization

P6-b200.48xlarge (8 GPUs, naive):
  [████ USED ████]                          → GPU 1: active
  [░░░░ IDLE ░░░░]                          → GPU 2: wasted
  [░░░░ IDLE ░░░░]                          → GPU 3: wasted
  [░░░░ IDLE ░░░░]                          → GPU 4: wasted
  [░░░░ IDLE ░░░░]                          → GPU 5: wasted
  [░░░░ IDLE ░░░░]                          → GPU 6: wasted
  [░░░░ IDLE ░░░░]                          → GPU 7: wasted
  [░░░░ IDLE ░░░░]                          → GPU 8: wasted
                                            → 12.5% utilization, 8x cost
```

## 4. Cost Scenarios for 100 Experiments

### Scenario A: 1 GPU = 1 Experiment (Current Pipeline Design)

Each SageMaker Training Job runs one experiment on one GPU.

| Instance | Training Time | Billable Time | Cost/Experiment | 100 Experiments |
|----------|-------------|---------------|-----------------|-----------------|
| **ml.p5.4xlarge** | 5 min | ~8 min | **$0.32** | **$32** |
| ml.p6-b200.48xlarge | 2.2 min (2.27x faster) | ~5.2 min | $3.45 (8 GPU billed) | $345 |
| ml.p6-b300.48xlarge | 1.5 min (3.4x faster) | ~4.5 min | $3.74 (8 GPU billed) | $374 |

**Result:** P6 is **10x more expensive** than P5 due to 7 idle GPUs.

### Scenario B: 8 GPU = 8 Experiments Simultaneously (P6 Optimized)

Modified pipeline: launch 8 experiments per P6 instance, one per GPU.

| Instance | Experiments/Job | Cost/Experiment | 100 Experiments | Wall Clock |
|----------|----------------|-----------------|-----------------|------------|
| **ml.p5.4xlarge** x10 parallel | 1 | $0.32 | **$32** | ~100 min |
| ml.p6-b200.48xlarge x2 parallel | 8 | $0.43 | $43 | ~40 min |
| ml.p6-b300.48xlarge x2 parallel | 8 | $0.47 | $47 | ~30 min |

**Result:** P6 is 1.3-1.5x more expensive but **2.5-3.3x faster** in wall clock time.

### Scenario C: Performance-Adjusted Cost (Tokens per Dollar)

Since B200/B300 process more tokens in the same 5-minute budget, we compare cost per billion tokens processed:

| GPU | Tokens in 5 min | Spot Cost (5 min) | Cost per B Tokens |
|-----|----------------|-------------------|-------------------|
| H100 (p5.4xl, 1 GPU) | ~500M | $0.20 | **$0.40/B** |
| B200 (p6-b200, 1 of 8 GPUs) | ~1,135M | $3.32 | $2.93/B (7.3x worse) |
| B200 (p6-b200, all 8 GPUs) | ~9,080M | $3.32 | **$0.37/B** (best) |

**Result:** P6 is **most cost-efficient per token** only when all 8 GPUs are fully utilized.

## 5. Summary & Recommendation

### Decision Matrix

| Priority | Best Choice | Reason |
|----------|------------|--------|
| **Cost efficiency** | **ml.p5.4xlarge** | Single GPU = zero waste, lowest $/experiment |
| **Time efficiency** | ml.p6-b200.48xlarge | 8 parallel experiments per instance, 2.5x faster |
| **Maximum throughput** | ml.p6-b300.48xlarge | 8 parallel + 3.4x per-GPU speedup |
| **Cost + Performance** | **ml.p5.4xlarge** | Best balance for autoresearch workload |

### Cost Summary Table

| | P5 (H100x1) | P6-B200 (naive) | P6-B200 (8-parallel) | P6-B300 (8-parallel) |
|---|---|---|---|---|
| 100 experiments cost | **$32** | $345 | $43 | $47 |
| Wall clock time | ~100 min | ~50 min | **~40 min** | **~30 min** |
| Cost per experiment | **$0.32** | $3.45 | $0.43 | $0.47 |
| GPU utilization | 100% | 12.5% | 100% | 100% |

### Recommendation

**Use ml.p5.4xlarge (H100 single GPU)** as the default for autoresearch:

1. **10x cheaper** than naive P6 usage
2. **Identical hardware** to the original autoresearch setup → fair comparison
3. **Simple pipeline** — one GPU per job, no multi-GPU orchestration needed
4. **Sufficient VRAM** (80 GB) for the 50M parameter model (~45 GB peak)

Consider P6 only if:
- Wall clock time is the top priority (board demo, deadline)
- Pipeline is modified to run 8 experiments per instance
- Budget is not a primary concern

---

## Appendix: P5 Spot Availability by Region

| Region | ml.p5.4xlarge Spot | ml.p5.48xlarge Spot |
|--------|-------------------|-------------------|
| us-west-2 (Oregon) | Quota exists (request needed) | Quota exists |
| ap-northeast-1 (Tokyo) | Quota exists (request needed) | Quota exists |
| eu-west-2 (London) | Available (On-Demand & Spot) | Available |
| ap-south-1 (Mumbai) | Available (On-Demand & Spot) | Available |
| ap-southeast-3 (Jakarta) | Available (On-Demand & Spot) | Available |
| sa-east-1 (Sao Paulo) | Available (On-Demand & Spot) | Available |

Source: [AWS P5 Instance Announcement (Aug 2025)](https://aws.amazon.com/about-aws/whats-new/2025/08/p5-instance-nvidia-h100-gpu-sagemaker-training-processing-jobs/)

---

*Analysis date: 2026-03-28*
*Prices are estimates based on publicly available data and may vary.*
