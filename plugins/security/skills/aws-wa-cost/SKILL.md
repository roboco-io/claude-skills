---
name: aws-wa-cost
description: AWS Well-Architected Cost Optimization Pillar review. Checks resource sizing, scaling, storage classes, and cost monitoring configurations in IaC code.
---

# Cost Optimization Pillar

비용 최적화, 탄력성, 구매 옵션 관점에서 IaC 코드를 검토합니다.

## 핵심 원칙

1. **클라우드 재무 관리 구현**: Cost Explorer, 예산
2. **소비 모델 채택**: 사용한 만큼 지불
3. **전체 효율성 측정**: 비용 대비 비즈니스 가치
4. **차별화되지 않는 과중한 작업 중단**: 관리형 서비스 활용
5. **비용 분석 및 귀속**: 태그 기반 비용 할당

## 검토 항목

### COST-01: 과도한 인스턴스 크기

| 심각도 | 탐지 유형 |
|--------|-----------|
| Medium | 자동 탐지 |

**검토 내용**: 개발/테스트 환경에서 과도한 인스턴스 크기 사용 여부

**Terraform 패턴**:
```hcl
# 검토 필요 - 개발 환경에 큰 인스턴스
resource "aws_instance" "dev" {
  instance_type = "m5.4xlarge"
  tags = {
    Environment = "dev"
  }
}

# 권장 - 환경에 맞는 크기
resource "aws_instance" "dev" {
  instance_type = "t3.medium"
  tags = {
    Environment = "dev"
  }
}
```

### COST-02: S3 스토리지 클래스

| 심각도 | 탐지 유형 |
|--------|-----------|
| Low | 자동 탐지 |

**검토 내용**: Intelligent-Tiering, Glacier 활용 여부

**Terraform 패턴**:
```hcl
# 권장 - Intelligent-Tiering
resource "aws_s3_bucket_intelligent_tiering_configuration" "good" {
  bucket = aws_s3_bucket.example.id
  name   = "EntireBucket"

  tiering {
    access_tier = "DEEP_ARCHIVE_ACCESS"
    days        = 180
  }
}

# 권장 - 수명 주기 정책
resource "aws_s3_bucket_lifecycle_configuration" "good" {
  bucket = aws_s3_bucket.example.id

  rule {
    id     = "archive"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
}
```

### COST-03: 미사용 리소스

| 심각도 | 탐지 유형 |
|--------|-----------|
| Medium | 자동 탐지 |

**검토 내용**: 미사용 EIP, 볼륨, 스냅샷 등 확인

**주의 항목**:
- 연결되지 않은 Elastic IP (비용 발생)
- 연결되지 않은 EBS 볼륨
- 오래된 스냅샷

### COST-04: 항상 실행되는 개발 환경

| 심각도 | 탐지 유형 |
|--------|-----------|
| Medium | 자동 탐지 |

**검토 내용**: 개발/테스트 환경이 24/7 실행되고 있는지 확인

**Terraform 패턴**:
```hcl
# 권장 - 예약된 스케일링
resource "aws_autoscaling_schedule" "scale_down" {
  scheduled_action_name  = "scale-down-evening"
  min_size               = 0
  max_size               = 0
  desired_capacity       = 0
  recurrence             = "0 19 * * MON-FRI"  # 저녁 7시
  autoscaling_group_name = aws_autoscaling_group.dev.name
}
```

### COST-05: Reserved Instance / Savings Plan

| 심각도 | 탐지 유형 |
|--------|-----------|
| Medium | 수동 확인 필요 |

**검토 내용**: 안정적인 워크로드에 RI/SP 적용 여부

**수동 확인 항목**:
- [ ] 프로덕션 인스턴스에 Reserved Instance 적용 여부
- [ ] Savings Plan 검토 여부
- [ ] Spot Instance 활용 가능 여부

### COST-06: 데이터 전송 비용

| 심각도 | 탐지 유형 |
|--------|-----------|
| Medium | 자동 탐지 |

**검토 내용**: 리전 간 데이터 전송, NAT Gateway 트래픽 최적화

**권장 사항**:
- VPC Endpoint 사용 (S3, DynamoDB 등)
- 같은 AZ 내 통신 최대화
- CloudFront 활용

**Terraform 패턴**:
```hcl
# 권장 - VPC Endpoint (NAT Gateway 비용 절감)
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.main.id
  service_name = "com.amazonaws.ap-northeast-2.s3"
}
```

### COST-07: 비용 알림

| 심각도 | 탐지 유형 |
|--------|-----------|
| Low | 자동 탐지 |

**검토 내용**: AWS Budgets, 비용 알림 설정 여부

**Terraform 패턴**:
```hcl
# 권장 - 예산 알림
resource "aws_budgets_budget" "monthly" {
  name              = "monthly-budget"
  budget_type       = "COST"
  limit_amount      = "1000"
  limit_unit        = "USD"
  time_period_start = "2024-01-01_00:00"
  time_unit         = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = ["team@example.com"]
  }
}
```

## IaC 플랫폼별 패턴

상세 패턴은 다음 참조:
- [Terraform 패턴](references/patterns/terraform.md)
- [CloudFormation 패턴](references/patterns/cloudformation.md)
- [CDK 패턴](references/patterns/cdk.md)
- [Pulumi 패턴](references/patterns/pulumi.md)

## 점수 산정

| 항목 | 가중치 |
|------|--------|
| 인스턴스 크기 적정성 | 25% |
| S3 스토리지 클래스 | 15% |
| 미사용 리소스 | 20% |
| 개발 환경 최적화 | 15% |
| Reserved/Savings | 15% |
| 비용 알림 | 10% |
