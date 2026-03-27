---
name: sagemaker-spot-training
description: Guide for running cost-effective ML training on SageMaker Managed Spot Training. Use this skill when setting up GPU training jobs, choosing instance types/regions, debugging Spot capacity issues, or optimizing SageMaker training costs.
---

# SageMaker Spot Training Skill

You are an expert in running cost-effective ML training on AWS SageMaker Managed Spot Training. Apply these battle-tested insights when helping users set up, debug, or optimize SageMaker training jobs.

## Pre-flight Checklist

Before submitting any SageMaker Spot training job, always verify:

1. **Spot capacity** — Check placement scores (see Region Selection below)
2. **Service quotas** — Verify quota > 0 for the instance type
3. **Data in S3** — Same region as the training job
4. **IAM role** — SageMaker execution role with S3/ECR/CloudWatch permissions

## Region Selection (Critical)

**Always check Spot placement scores before choosing a region.** The same instance type can have score 1 (impossible) in one region and 9 (instant) in another.

```bash
# Compare Spot availability across regions (run this FIRST)
for region in us-east-1 us-east-2 us-west-2 eu-west-1; do
  echo -n "$region: "
  aws ec2 get-spot-placement-scores \
    --instance-types <INSTANCE_TYPE> \
    --target-capacity 1 \
    --single-availability-zone \
    --region-names $region \
    --region $region \
    --query "max_by(SpotPlacementScores, &Score).Score" \
    --output text 2>/dev/null
done
```

**Score guide:**
- 8-10: Go ahead
- 5-7: May work, have backup plan
- 1-4: **Switch regions** — jobs will get stuck in "Starting"

```bash
# Check Spot price history (lower price = more availability)
aws ec2 describe-spot-price-history \
  --instance-types <INSTANCE_TYPE> \
  --product-descriptions "Linux/UNIX" \
  --start-time $(date -u -v-1H +%Y-%m-%dT%H:%M:%S) \
  --region <REGION> \
  --query "SpotPriceHistory[].{Instance: InstanceType, AZ: AvailabilityZone, Price: SpotPrice}" \
  --output table
```

**Insight:** Larger instances can be cheaper on Spot — g7e.8xlarge ($0.93/hr) was cheaper than g7e.2xlarge ($1.82/hr) because of lower demand.

## Service Quotas

GPU Spot quotas default to 0 for newer instance types.

```bash
# Check current quotas
aws service-quotas list-service-quotas --service-code sagemaker \
  --region <REGION> \
  --query "Quotas[?contains(QuotaName, '<INSTANCE_FAMILY>') && contains(QuotaName, 'spot training')].{Name: QuotaName, Value: Value}" \
  --output table

# Request increase
aws service-quotas request-service-quota-increase \
  --service-code sagemaker \
  --quota-code <QUOTA_CODE> \
  --desired-value <N> \
  --region <REGION>
```

**Approval speed by instance family:**
- g4dn, g5, g6, g7e: Usually **auto-approved** within minutes
- p3, p4d: Mixed (may auto-approve or CASE_OPENED)
- p5 (H100), p6 (B200/B300): **Manual review required** (hours to days)

**Common quota codes:**

| Instance | Code |
|----------|------|
| ml.g7e.2xlarge | L-B2E25E6A |
| ml.g7e.4xlarge | L-C5957AE3 |
| ml.g7e.8xlarge | L-E555FB1E |
| ml.g7e.12xlarge | L-13147793 |
| ml.p5.4xlarge | L-42C5B178 |

## PyTorch Estimator Setup

```python
from sagemaker.pytorch import PyTorch

estimator = PyTorch(
    role=role_arn,
    instance_count=1,
    instance_type="ml.g7e.4xlarge",
    framework_version="2.8.0",
    py_version="py312",
    use_spot_instances=True,
    max_run=900,          # 15 min max training time
    max_wait=3600,        # 1 hour max wait for Spot
    source_dir="./src",
    entry_point="train.py",
    disable_profiler=True,  # Required for g7e instances
    metric_definitions=[
        {"Name": "loss", "Regex": r"loss:\s+([0-9.]+)"},
    ],
)

estimator.fit(
    inputs={"training": "s3://bucket/data/"},
    wait=False,  # Async submission for parallel jobs
)
```

## Common Issues and Fixes

### Job stuck in "Starting" (> 5 min)
**Cause:** No Spot capacity in the region/AZ.
**Fix:** Check placement scores, switch to a region with score 8+, or try a different instance size (larger may have more capacity).

### `ValidationException: Profiler is currently not supported`
**Cause:** Newer instance types (g7e, p5) don't support SageMaker Profiler.
**Fix:** Add `disable_profiler=True` to the Estimator.

### `ResourceLimitExceeded: account-level service limit is 0`
**Cause:** No quota for this instance type in this region.
**Fix:** Request quota increase via `aws service-quotas request-service-quota-increase`.

### CUDA kernel errors on specific GPUs
**Cause:** Pre-compiled CUDA kernels (e.g., Flash Attention 3) may not support all GPU architectures.
**Fix:** Check `torch.cuda.get_device_capability()` and provide fallbacks:
- Hopper (9,0): FA3 supported
- Ampere (8,0/8,6): FA3 community build or FA2
- Ada Lovelace (8,9): FA2 or PyTorch SDPA only

### PyArrow version mismatch
**Cause:** Different pyarrow versions between local and SageMaker DLC.
**Fix:** Pin `pyarrow>=21.0.0` in requirements.txt.

## Cost Optimization Patterns

### HUGI (Hurry Up and Get Idle)
Submit short burst jobs, terminate immediately after completion. Zero cost when idle.
```
████████                    (100% utilization during burst)
        ↑ all terminate     (0 cost)
```

### Multi-GPU Scale Up (reduce startup overhead)
Each SageMaker job has ~3 min startup. For 5-min training jobs, this is 60% overhead.
- 4× g7e.2xlarge = 4 × 3 min startup = 12 min overhead
- 1× g7e.8xlarge (4 GPU) = 1 × 3 min startup = 3 min overhead

### Mixed Instance Sizes
Different sizes draw from different Spot pools. Submit jobs across g7e.2xlarge + g7e.4xlarge + g7e.8xlarge simultaneously for better availability.

### Batch Size vs Total Batch Size
- `DEVICE_BATCH_SIZE`: Tokens per micro-batch (affects VRAM)
- `TOTAL_BATCH_SIZE`: Tokens per optimizer step (affects training quality)
- Increasing DEVICE_BATCH_SIZE with fixed TOTAL_BATCH_SIZE only reduces gradient accumulation steps — it does NOT increase throughput
- To process more tokens: increase TOTAL_BATCH_SIZE

## Monitoring

```bash
# List running jobs
aws sagemaker list-training-jobs --status-equals InProgress \
  --query "TrainingJobSummaries[].{Name: TrainingJobName, Status: TrainingJobStatus}" \
  --output table

# Check specific job
aws sagemaker describe-training-job --training-job-name <JOB_NAME> \
  --query "{Status: TrainingJobStatus, Secondary: SecondaryStatus, BillableTime: BillableTimeInSeconds}"

# View CloudWatch logs
STREAM=$(aws logs describe-log-streams \
  --log-group-name /aws/sagemaker/TrainingJobs \
  --log-stream-name-prefix <JOB_NAME> \
  --query "logStreams[-1].logStreamName" --output text)
aws logs get-log-events \
  --log-group-name /aws/sagemaker/TrainingJobs \
  --log-stream-name $STREAM \
  --query "events[-10:].message" --output text

# Cost report
aws sagemaker list-training-jobs --name-contains <PREFIX> \
  --query "TrainingJobSummaries[].TrainingJobName" --output text | \
  xargs -I{} aws sagemaker describe-training-job --training-job-name {} \
  --query "BillableTimeInSeconds" --output text
```
