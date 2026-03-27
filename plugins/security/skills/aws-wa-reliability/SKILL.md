---
name: aws-wa-reliability
description: AWS Well-Architected Reliability Pillar review. Checks high availability, fault tolerance, backup, and disaster recovery configurations in IaC code.
---

# Reliability Pillar

장애 복구, 확장성, 고가용성 관점에서 IaC 코드를 검토합니다.

## 핵심 원칙

1. **장애로부터 자동 복구**: Auto Scaling, Health Check
2. **복구 절차 테스트**: DR 테스트
3. **수평 확장**: Multi-AZ, Auto Scaling
4. **용량 추측 중단**: 메트릭 기반 스케일링
5. **변경 관리 자동화**: IaC, CI/CD

## 검토 항목

### REL-01: Multi-AZ 배포

| 심각도 | 탐지 유형 |
|--------|-----------|
| Critical | 자동 탐지 |

**검토 내용**: 주요 리소스가 Multi-AZ로 배포되어 있는지 확인

**Terraform 패턴**:
```hcl
# 취약 - 단일 AZ
resource "aws_db_instance" "bad" {
  multi_az = false
}

# 안전 - Multi-AZ
resource "aws_db_instance" "good" {
  multi_az = true
}
```

### REL-02: Auto Scaling

| 심각도 | 탐지 유형 |
|--------|-----------|
| High | 자동 탐지 |

**검토 내용**: Auto Scaling Group이 설정되어 있는지 확인

**Terraform 패턴**:
```hcl
# 안전 - Auto Scaling 설정
resource "aws_autoscaling_group" "good" {
  min_size         = 2
  max_size         = 10
  desired_capacity = 2

  health_check_type         = "ELB"
  health_check_grace_period = 300
}
```

### REL-03: 백업 설정

| 심각도 | 탐지 유형 |
|--------|-----------|
| High | 자동 탐지 |

**검토 내용**: RDS, EBS 등의 자동 백업이 설정되어 있는지 확인

**Terraform 패턴**:
```hcl
# 취약 - 백업 비활성화
resource "aws_db_instance" "bad" {
  backup_retention_period = 0
}

# 안전 - 백업 활성화
resource "aws_db_instance" "good" {
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
}
```

### REL-04: Health Check

| 심각도 | 탐지 유형 |
|--------|-----------|
| High | 자동 탐지 |

**검토 내용**: ALB/NLB에 적절한 Health Check가 설정되어 있는지 확인

**Terraform 패턴**:
```hcl
# 안전 - Health Check 설정
resource "aws_lb_target_group" "good" {
  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/health"
    matcher             = "200"
  }
}
```

### REL-05: S3 복제

| 심각도 | 탐지 유형 |
|--------|-----------|
| Medium | 자동 탐지 |

**검토 내용**: 중요 데이터에 Cross-Region Replication이 설정되어 있는지 확인

### REL-06: 단일 NAT Gateway

| 심각도 | 탐지 유형 |
|--------|-----------|
| Medium | 자동 탐지 |

**검토 내용**: 각 AZ에 NAT Gateway가 있는지 확인 (단일 실패 지점 방지)

**Terraform 패턴**:
```hcl
# 취약 - 단일 NAT Gateway
resource "aws_nat_gateway" "single" {
  subnet_id = aws_subnet.public_a.id
}

# 안전 - AZ별 NAT Gateway
resource "aws_nat_gateway" "az_a" {
  subnet_id = aws_subnet.public_a.id
}

resource "aws_nat_gateway" "az_b" {
  subnet_id = aws_subnet.public_b.id
}
```

### REL-07: RTO/RPO 정의

| 심각도 | 탐지 유형 |
|--------|-----------|
| Medium | 수동 확인 필요 |

**검토 내용**: RTO(복구 시간 목표)와 RPO(복구 지점 목표)가 정의되어 있는지 확인

**수동 확인 항목**:
- [ ] RTO가 문서화되어 있는가?
- [ ] RPO가 문서화되어 있는가?
- [ ] 백업 주기가 RPO와 일치하는가?

### REL-08: 재해 복구 계획

| 심각도 | 탐지 유형 |
|--------|-----------|
| Medium | 수동 확인 필요 |

**검토 내용**: DR 계획이 존재하고 테스트되었는지 확인

## IaC 플랫폼별 패턴

상세 패턴은 다음 참조:
- [Terraform 패턴](references/patterns/terraform.md)
- [CloudFormation 패턴](references/patterns/cloudformation.md)
- [CDK 패턴](references/patterns/cdk.md)
- [Pulumi 패턴](references/patterns/pulumi.md)

## 점수 산정

| 항목 | 가중치 |
|------|--------|
| Multi-AZ 배포 | 25% |
| Auto Scaling | 20% |
| 백업 설정 | 20% |
| Health Check | 15% |
| S3 복제 | 10% |
| RTO/RPO | 10% |
