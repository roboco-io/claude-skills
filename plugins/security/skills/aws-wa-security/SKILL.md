---
name: aws-wa-security
description: AWS Well-Architected Security Pillar review. Checks IAM, encryption, network security, and detective controls in IaC code. Integrates with owasp-review for application code.
---

# Security Pillar

데이터 보호, ID/접근 관리, 탐지 제어 관점에서 IaC 코드를 검토합니다.

## 핵심 원칙

1. **강력한 자격 증명 기반**: IAM, MFA
2. **추적 가능성 활성화**: CloudTrail, 로깅
3. **모든 계층에 보안 적용**: VPC, Security Group, WAF
4. **보안 모범 사례 자동화**: Security Hub, Config
5. **전송 중/저장 데이터 보호**: 암호화, KMS

## 검토 항목

### SEC-01: IAM 최소 권한

| 심각도 | 탐지 유형 |
|--------|-----------|
| Critical | 자동 탐지 |

**검토 내용**: IAM 정책이 최소 권한 원칙을 준수하는지 확인

**Terraform 패턴**:
```hcl
# 취약 - 과도한 권한
resource "aws_iam_policy" "bad" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# 안전 - 최소 권한
resource "aws_iam_policy" "good" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "arn:aws:s3:::my-bucket/*"
    }]
  })
}
```

### SEC-02: S3 암호화

| 심각도 | 탐지 유형 |
|--------|-----------|
| Critical | 자동 탐지 |

**검토 내용**: S3 버킷에 서버 측 암호화가 설정되어 있는지 확인

**Terraform 패턴**:
```hcl
# 취약 - 암호화 없음
resource "aws_s3_bucket" "bad" {
  bucket = "my-bucket"
}

# 안전 - KMS 암호화
resource "aws_s3_bucket_server_side_encryption_configuration" "good" {
  bucket = aws_s3_bucket.example.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.mykey.arn
    }
  }
}
```

### SEC-03: RDS 암호화

| 심각도 | 탐지 유형 |
|--------|-----------|
| Critical | 자동 탐지 |

**검토 내용**: RDS 인스턴스에 암호화가 설정되어 있는지 확인

**Terraform 패턴**:
```hcl
# 취약
resource "aws_db_instance" "bad" {
  storage_encrypted = false
}

# 안전
resource "aws_db_instance" "good" {
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}
```

### SEC-04: Security Group 규칙

| 심각도 | 탐지 유형 |
|--------|-----------|
| Critical | 자동 탐지 |

**검토 내용**: 0.0.0.0/0 인바운드 규칙 확인 (SSH/RDP)

**Terraform 패턴**:
```hcl
# 취약 - 전체 IP 허용
resource "aws_security_group_rule" "bad" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

# 안전 - 특정 IP만 허용
resource "aws_security_group_rule" "good" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
}
```

### SEC-05: VPC Flow Logs

| 심각도 | 탐지 유형 |
|--------|-----------|
| High | 자동 탐지 |

**검토 내용**: VPC에 Flow Logs가 활성화되어 있는지 확인

### SEC-06: GuardDuty

| 심각도 | 탐지 유형 |
|--------|-----------|
| High | 자동 탐지 |

**검토 내용**: GuardDuty가 활성화되어 있는지 확인

### SEC-07: KMS 키 로테이션

| 심각도 | 탐지 유형 |
|--------|-----------|
| High | 자동 탐지 |

**검토 내용**: KMS 키 자동 로테이션이 활성화되어 있는지 확인

### SEC-08: 퍼블릭 S3 버킷

| 심각도 | 탐지 유형 |
|--------|-----------|
| Critical | 자동 탐지 |

**검토 내용**: S3 버킷이 퍼블릭으로 설정되어 있는지 확인

**Terraform 패턴**:
```hcl
# 취약
resource "aws_s3_bucket_public_access_block" "bad" {
  bucket                  = aws_s3_bucket.example.id
  block_public_acls       = false
  block_public_policy     = false
}

# 안전
resource "aws_s3_bucket_public_access_block" "good" {
  bucket                  = aws_s3_bucket.example.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## owasp-review 연동

애플리케이션 코드 발견 시 owasp-review 스킬 참조 제안:
- `src/`, `app/`, `lib/` 등 애플리케이션 디렉토리 감지
- 사용자 확인 후 OWASP 보안 리뷰 수행

## IaC 플랫폼별 패턴

상세 패턴은 다음 참조:
- [Terraform 패턴](references/patterns/terraform.md)
- [CloudFormation 패턴](references/patterns/cloudformation.md)
- [CDK 패턴](references/patterns/cdk.md)
- [Pulumi 패턴](references/patterns/pulumi.md)

## Compliance 매핑

| 항목 | PCI-DSS | HIPAA | SOC2 |
|------|---------|-------|------|
| IAM 최소 권한 | 7.1 | §164.312(a)(1) | CC6.3 |
| 데이터 암호화 | 3.4 | §164.312(a)(2)(iv) | CC6.1 |
| 네트워크 보안 | 1.3 | §164.312(e)(1) | CC6.6 |

## 점수 산정

| 항목 | 가중치 |
|------|--------|
| IAM 최소 권한 | 20% |
| 데이터 암호화 (S3, RDS, EBS) | 25% |
| 네트워크 보안 | 20% |
| 탐지 제어 (GuardDuty, Flow Logs) | 20% |
| KMS 관리 | 15% |
