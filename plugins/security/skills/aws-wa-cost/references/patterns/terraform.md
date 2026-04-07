# Cost Optimization Pillar - Terraform 패턴

## 환경별 인스턴스 크기 분리

```hcl
locals {
  instance_types = {
    dev  = "t3.small"
    prod = "m6i.large"
  }
}

resource "aws_instance" "app" {
  instance_type = local.instance_types[var.environment]
}
```

## S3 Lifecycle 정책

```hcl
resource "aws_s3_bucket_lifecycle_configuration" "cost" {
  bucket = aws_s3_bucket.main.id
  rule {
    id     = "archive"
    status = "Enabled"
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    expiration { days = 365 }
  }
}
```

## Spot 인스턴스 활용

```hcl
resource "aws_autoscaling_group" "spot" {
  mixed_instances_policy {
    instances_distribution {
      on_demand_percentage_above_base_capacity = 30
      spot_allocation_strategy                 = "capacity-optimized"
    }
    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.app.id
      }
      override { instance_type = "m6i.large" }
      override { instance_type = "m5.large" }
    }
  }
}
```

## 비용 태깅

```hcl
resource "aws_instance" "app" {
  tags = {
    Environment = var.environment
    Project     = var.project
    CostCenter  = var.cost_center
    Owner       = var.team
  }
}
```
