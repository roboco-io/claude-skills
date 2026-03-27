---
name: aws-wa-sustainability
description: AWS Well-Architected Sustainability Pillar review. Checks energy efficiency, resource optimization, and sustainable practices in IaC code.
---

# Sustainability Pillar

환경 영향 최소화, 에너지 효율 관점에서 IaC 코드를 검토합니다.

## 핵심 원칙

1. **영향 이해**: 탄소 발자국 측정
2. **지속 가능성 목표 수립**: 환경 목표 설정
3. **활용 극대화**: 리소스 효율성 최대화
4. **더 효율적인 하드웨어/소프트웨어 채택**: Graviton, Serverless
5. **관리형 서비스 사용**: 공유 인프라 활용
6. **다운스트림 영향 축소**: 데이터 전송 최적화

## 검토 항목

### SUS-01: Graviton 인스턴스 사용

| 심각도 | 탐지 유형 |
|--------|-----------|
| Low | 자동 탐지 |

**검토 내용**: 에너지 효율적인 Graviton 프로세서 사용 여부

**Graviton 장점**:
- 최대 60% 에너지 효율 향상
- 동일 성능 대비 낮은 비용

**Terraform 패턴**:
```hcl
# 권장 - Graviton 인스턴스
resource "aws_instance" "sustainable" {
  instance_type = "t4g.medium"  # Graviton2
}

resource "aws_instance" "sustainable_v3" {
  instance_type = "m7g.large"   # Graviton3
}
```

### SUS-02: Serverless 활용

| 심각도 | 탐지 유형 |
|--------|-----------|
| Low | 자동 탐지 |

**검토 내용**: Lambda, Fargate 등 서버리스 서비스 활용 여부

**권장 서비스**:
- AWS Lambda
- AWS Fargate
- Amazon Aurora Serverless
- Amazon DynamoDB On-Demand

**Terraform 패턴**:
```hcl
# 권장 - Lambda 사용
resource "aws_lambda_function" "sustainable" {
  function_name = "my-function"
  runtime       = "python3.11"
  # 사용하지 않을 때 리소스 소비 없음
}

# 권장 - Fargate 사용
resource "aws_ecs_service" "sustainable" {
  launch_type = "FARGATE"
}
```

### SUS-03: 관리형 서비스 활용

| 심각도 | 탐지 유형 |
|--------|-----------|
| Low | 자동 탐지 |

**검토 내용**: 자체 관리 대신 관리형 서비스 사용 여부

**권장 서비스**:
- Amazon RDS (vs 자체 관리 DB)
- Amazon ElastiCache (vs 자체 관리 Redis)
- Amazon OpenSearch Service
- Amazon MQ

### SUS-04: 리소스 적정 규모

| 심각도 | 탐지 유형 |
|--------|-----------|
| Low | 자동 탐지 |

**검토 내용**: 과도한 크기의 인스턴스 사용 여부 (Cost Pillar와 연계)

### SUS-05: 저탄소 리전

| 심각도 | 탐지 유형 |
|--------|-----------|
| Low | 수동 확인 필요 |

**검토 내용**: 지속 가능한 에너지를 사용하는 리전 선택 여부

**AWS 저탄소 리전** (재생 에너지 비율 높음):
- eu-north-1 (Stockholm)
- eu-west-1 (Ireland)
- us-west-2 (Oregon)
- ca-central-1 (Canada)

### SUS-06: 미사용 리소스 정리

| 심각도 | 탐지 유형 |
|--------|-----------|
| Low | 자동 탐지 |

**검토 내용**: 미사용 리소스 방치 여부 (Cost Pillar와 연계)

**체크 항목**:
- 미사용 EBS 볼륨
- 오래된 스냅샷
- 미사용 Elastic IP
- 유휴 로드 밸런서

### SUS-07: 데이터 저장 최적화

| 심각도 | 탐지 유형 |
|--------|-----------|
| Low | 자동 탐지 |

**검토 내용**: 데이터 수명 주기 정책, 압축 사용 여부

**Terraform 패턴**:
```hcl
# 권장 - 수명 주기 정책
resource "aws_s3_bucket_lifecycle_configuration" "sustainable" {
  bucket = aws_s3_bucket.example.id

  rule {
    id     = "cleanup"
    status = "Enabled"

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}
```

### SUS-08: 효율적인 코드

| 심각도 | 탐지 유형 |
|--------|-----------|
| Low | 수동 확인 필요 |

**검토 내용**: 효율적인 프로그래밍 언어/런타임 사용 여부

**에너지 효율 순위** (일반적):
1. Rust, C, C++
2. Go, Java
3. Python, Node.js, Ruby

## IaC 플랫폼별 패턴

상세 패턴은 다음 참조:
- [Terraform 패턴](references/patterns/terraform.md)
- [CloudFormation 패턴](references/patterns/cloudformation.md)
- [CDK 패턴](references/patterns/cdk.md)
- [Pulumi 패턴](references/patterns/pulumi.md)

## 점수 산정

| 항목 | 가중치 |
|------|--------|
| Graviton 사용 | 25% |
| Serverless 활용 | 25% |
| 관리형 서비스 | 20% |
| 리소스 적정 규모 | 15% |
| 데이터 최적화 | 15% |

## AWS 지속 가능성 리소스

- [AWS Customer Carbon Footprint Tool](https://aws.amazon.com/aws-cost-management/aws-customer-carbon-footprint-tool/)
- [AWS 지속 가능성](https://sustainability.aboutamazon.com/environment/the-cloud)
