# Operational Excellence Pillar - Terraform 패턴

## CloudWatch 모니터링

```hcl
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_actions       = [aws_sns_topic.alerts.arn]
}
```

## SSM Parameter Store 활용

```hcl
resource "aws_ssm_parameter" "db_password" {
  name  = "/${var.environment}/db/password"
  type  = "SecureString"
  value = var.db_password
}
```

## IaC 상태 관리

```hcl
terraform {
  backend "s3" {
    bucket         = "terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "ap-northeast-2"
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
}
```

## 자동 배포 파이프라인

```hcl
resource "aws_codepipeline" "deploy" {
  name     = "app-pipeline"
  role_arn = aws_iam_role.pipeline.arn
  stage {
    name = "Deploy"
    action {
      name            = "Deploy"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "ECS"
      input_artifacts = ["build_output"]
      version         = "1"
    }
  }
}
```
