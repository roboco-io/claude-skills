# Sustainability Pillar - Terraform 패턴

## Graviton 인스턴스 활용

```hcl
resource "aws_instance" "efficient" {
  ami           = data.aws_ami.al2023_arm.id
  instance_type = "m7g.large"  # Graviton3 - 최대 60% 에너지 효율 향상
}
```

## 자동 스케일링 (유휴 리소스 최소화)

```hcl
resource "aws_appautoscaling_target" "ecs" {
  max_capacity       = 10
  min_capacity       = 1
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.app.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "scale_to_zero" {
  name               = "scale-down"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value = 70.0
  }
}
```

## S3 Intelligent-Tiering

```hcl
resource "aws_s3_bucket_intelligent_tiering_configuration" "auto" {
  bucket = aws_s3_bucket.main.id
  name   = "auto-tier"
  tiering {
    access_tier = "ARCHIVE_ACCESS"
    days        = 90
  }
}
```

## 리전 선택 (저탄소)

```hcl
provider "aws" {
  region = "eu-north-1"  # 스웨덴 - 재생에너지 비율 높음
}
```
