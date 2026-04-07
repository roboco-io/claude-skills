# Security Pillar - Terraform 패턴

## IAM 최소 권한

```hcl
# 권장 - 리소스 및 액션 제한
resource "aws_iam_policy" "app_policy" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "arn:aws:s3:::my-bucket/*"
    }]
  })
}
```

## 전송 중 암호화

```hcl
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.main.arn
}
```

## 저장 데이터 암호화

```hcl
resource "aws_s3_bucket_server_side_encryption_configuration" "enc" {
  bucket = aws_s3_bucket.main.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
  }
}
```

## Security Group 최소 개방

```hcl
resource "aws_security_group_rule" "app" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/16"]
  security_group_id = aws_security_group.app.id
}
```
