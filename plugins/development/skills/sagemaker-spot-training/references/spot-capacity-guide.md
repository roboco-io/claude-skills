# Spot Capacity Guide: How to Choose the Right Region and Instance

> A practical guide for finding available GPU Spot capacity on SageMaker before wasting time on stuck "Starting" jobs.

## The Problem

SageMaker Managed Spot Training can get stuck in "Starting" status indefinitely when Spot capacity is unavailable. We experienced this firsthand:

- **us-west-2 (Oregon)**: ml.g7e.2xlarge and ml.g7e.4xlarge stuck in "Starting" for 30+ minutes
- **us-east-1 (Virginia)**: Same instances allocated within 2 minutes

The difference: Spot placement score of **1-2** (Oregon) vs **9** (Virginia).

## Step 1: Check Spot Placement Scores

The `get-spot-placement-scores` API gives a 1-10 score predicting Spot request success likelihood.

```bash
# Check scores for target instance types across a region
aws ec2 get-spot-placement-scores \
  --instance-types g7e.2xlarge g7e.4xlarge g7e.8xlarge \
  --target-capacity 1 \
  --single-availability-zone \
  --region-names us-west-2 \
  --profile YOUR_PROFILE \
  --region us-west-2 \
  --query "SpotPlacementScores[].{AZ: AvailabilityZoneId, Score: Score}" \
  --output table
```

**Score interpretation:**

| Score | Meaning | Action |
|-------|---------|--------|
| 8-10 | High likelihood | Go ahead |
| 5-7 | Moderate | May work, have backup plan |
| 3-4 | Low | Expect delays |
| **1-2** | **Very low** | **Switch regions** |

### Multi-region comparison (recommended)

```bash
# Compare scores across multiple regions in one shot
for region in us-east-1 us-east-2 us-west-2 eu-west-1 ap-northeast-1; do
  echo -n "$region: "
  aws ec2 get-spot-placement-scores \
    --instance-types g7e.2xlarge g7e.4xlarge g7e.8xlarge \
    --target-capacity 1 \
    --single-availability-zone \
    --region-names $region \
    --profile YOUR_PROFILE \
    --region $region \
    --query "max_by(SpotPlacementScores, &Score).Score" \
    --output text 2>&1
done
```

## Step 2: Check Spot Price History

Spot prices reflect supply/demand — lower prices often mean more availability.

```bash
aws ec2 describe-spot-price-history \
  --instance-types g7e.2xlarge g7e.4xlarge g7e.8xlarge \
  --product-descriptions "Linux/UNIX" \
  --start-time $(date -u -v-1H +%Y-%m-%dT%H:%M:%S) \
  --profile YOUR_PROFILE \
  --region us-east-1 \
  --query "SpotPriceHistory[].{Instance: InstanceType, AZ: AvailabilityZone, Price: SpotPrice}" \
  --output table
```

**Key insight from our experiment:** g7e.8xlarge was actually **cheaper** ($0.93/hr) than g7e.2xlarge ($0.94-$1.82/hr) in us-west-2. Larger instances sometimes have less demand and better Spot availability.

## Step 3: Check Service Quotas

Even with Spot capacity, you need SageMaker service quotas.

```bash
# Check existing quotas
aws service-quotas list-service-quotas --service-code sagemaker \
  --profile YOUR_PROFILE --region us-east-1 \
  --query "Quotas[?contains(QuotaName, 'g7e') && contains(QuotaName, 'spot training')].{Name: QuotaName, Value: Value}" \
  --output table

# Request increase
aws service-quotas request-service-quota-increase \
  --service-code sagemaker \
  --quota-code L-C5957AE3 \
  --desired-value 4 \
  --profile YOUR_PROFILE \
  --region us-east-1
```

**Quota codes for common GPU instances:**

| Instance | Quota Code | GPU |
|----------|-----------|-----|
| ml.g7e.2xlarge | L-B2E25E6A | L40S 48GB |
| ml.g7e.4xlarge | L-C5957AE3 | L40S 48GB |
| ml.g7e.8xlarge | L-E555FB1E | L40S 48GB |
| ml.g7e.12xlarge | L-13147793 | L40S 96GB (2x) |
| ml.p5.4xlarge | L-42C5B178 | H100 80GB |

**Approval speed:** g7e instances were auto-approved within minutes. p5 (H100) requires manual review (CASE_OPENED).

## Our Region Selection Journey

| Date | Region | Instance | Result | Reason |
|------|--------|----------|--------|--------|
| Mar 27 | ap-northeast-1 | ml.p5.4xlarge | Quota 0, CASE_OPENED | H100 needs manual review |
| Mar 28 | us-west-2 | ml.g7e.4xlarge | Stuck "Starting" 30+ min | Spot score 1-2 |
| Mar 28 | us-west-2 | ml.g7e.2xlarge | Stuck "Starting" | Same Spot pool issue |
| **Mar 28** | **us-east-1** | **ml.g7e.2xlarge** | **Allocated in ~2 min** | **Spot score 9** |

## Best Practices

1. **Always check Spot placement scores before choosing a region** — 30 seconds of CLI saves 30+ minutes of waiting
2. **Compare multiple regions** — Spot capacity varies dramatically (score 1 vs 9)
3. **Request quotas in advance** — g7e auto-approves, but p5/p6 need manual review
4. **Consider larger instances** — Sometimes cheaper and more available (less demand)
5. **Use `max_wait` in SageMaker** — Set a reasonable timeout so stuck jobs don't run forever
6. **Have a fallback region** — Keep data uploaded in 2+ regions for quick switching

## Quick Decision Script

```bash
#!/bin/bash
# find-best-spot-region.sh — Find the best region for a given instance type
INSTANCE=${1:-g7e.4xlarge}
REGIONS="us-east-1 us-east-2 us-west-2 eu-west-1 ap-northeast-1"

echo "Spot placement scores for $INSTANCE:"
echo "---"
for region in $REGIONS; do
  score=$(aws ec2 get-spot-placement-scores \
    --instance-types $INSTANCE \
    --target-capacity 1 \
    --single-availability-zone \
    --region-names $region \
    --region $region \
    --query "max_by(SpotPlacementScores, &Score).Score" \
    --output text 2>/dev/null)
  printf "%-20s Score: %s\n" "$region" "${score:-N/A}"
done
```

---

*Based on real experience running serverless-autoresearch experiments, March 2026.*
