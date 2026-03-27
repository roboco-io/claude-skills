---
name: aws-wa-operational-excellence
description: AWS Well-Architected Operational Excellence Pillar review. Checks monitoring, logging, deployment automation, and continuous improvement practices in IaC code.
---

# Operational Excellence Pillar

운영 효율성, 모니터링, 지속적 개선 관점에서 IaC 코드를 검토합니다.

## 핵심 원칙

1. **운영을 코드로 수행**: IaC, 자동화된 배포
2. **작고 가역적인 변경**: 점진적 배포, 롤백 가능
3. **운영 절차 개선**: 런북, 플레이북
4. **장애 예측**: 모니터링, 알람
5. **모든 장애로부터 학습**: 로깅, 분석

## 검토 항목

### OPS-01: CloudWatch 로그 그룹

| 심각도 | 탐지 유형 |
|--------|-----------|
| High | 자동 탐지 |

**검토 내용**: 모든 리소스에 CloudWatch 로그 그룹이 설정되어 있는지 확인

**Terraform 패턴**:
```hcl
# 취약 - 로그 그룹 없음
resource "aws_lambda_function" "example" {
  function_name = "my-function"
  # CloudWatch 로그 설정 없음
}

# 안전 - 로그 그룹 설정
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/my-function"
  retention_in_days = 14
}
```

### OPS-02: CloudWatch 알람

| 심각도 | 탐지 유형 |
|--------|-----------|
| High | 자동 탐지 |

**검토 내용**: 주요 메트릭에 대한 알람이 설정되어 있는지 확인

**Terraform 패턴**:
```hcl
# 안전 - 알람 설정
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "high-cpu-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}
```

### OPS-03: X-Ray 트레이싱

| 심각도 | 탐지 유형 |
|--------|-----------|
| Medium | 자동 탐지 |

**검토 내용**: 분산 트레이싱이 활성화되어 있는지 확인

**Terraform 패턴**:
```hcl
# 취약 - 트레이싱 비활성화
resource "aws_lambda_function" "example" {
  tracing_config {
    mode = "PassThrough"
  }
}

# 안전 - 트레이싱 활성화
resource "aws_lambda_function" "example" {
  tracing_config {
    mode = "Active"
  }
}
```

### OPS-04: 태그 지정

| 심각도 | 탐지 유형 |
|--------|-----------|
| Low | 자동 탐지 |

**검토 내용**: 리소스에 적절한 태그가 지정되어 있는지 확인

**필수 태그**:
- `Environment`: dev/staging/prod
- `Project`: 프로젝트 이름
- `Owner`: 담당자/팀
- `CostCenter`: 비용 센터

### OPS-05: 런북/플레이북

| 심각도 | 탐지 유형 |
|--------|-----------|
| Low | 수동 확인 필요 |

**검토 내용**: 운영 문서가 존재하는지 확인

**수동 확인 항목**:
- [ ] 인시던트 대응 절차 문서화
- [ ] 배포 롤백 절차 문서화
- [ ] 장애 복구 절차 문서화

## IaC 플랫폼별 패턴

상세 패턴은 다음 참조:
- [Terraform 패턴](references/patterns/terraform.md)
- [CloudFormation 패턴](references/patterns/cloudformation.md)
- [CDK 패턴](references/patterns/cdk.md)
- [Pulumi 패턴](references/patterns/pulumi.md)

## 점수 산정

| 항목 | 가중치 |
|------|--------|
| CloudWatch 로그 | 25% |
| CloudWatch 알람 | 25% |
| X-Ray 트레이싱 | 20% |
| 태그 지정 | 15% |
| 런북/플레이북 | 15% |
