# Reliability Pillar - Terraform 패턴

## Multi-AZ 배포

```hcl
resource "aws_db_instance" "main" {
  multi_az             = true
  engine               = "postgres"
  instance_class       = "db.r6g.large"
  backup_retention_period = 7
  storage_encrypted    = true
}
```

## Auto Scaling

```hcl
resource "aws_autoscaling_group" "app" {
  min_size         = 2
  max_size         = 10
  desired_capacity = 2
  health_check_type         = "ELB"
  health_check_grace_period = 300

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }
}
```

## S3 버전 관리 및 복제

```hcl
resource "aws_s3_bucket_versioning" "main" {
  bucket = aws_s3_bucket.main.id
  versioning_configuration {
    status = "Enabled"
  }
}
```

## 장애 조치 라우팅

```hcl
resource "aws_route53_health_check" "primary" {
  fqdn              = "primary.example.com"
  port               = 443
  type               = "HTTPS"
  request_interval   = 10
  failure_threshold  = 3
}
```
