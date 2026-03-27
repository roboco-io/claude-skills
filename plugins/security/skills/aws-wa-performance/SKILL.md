---
name: aws-wa-performance
description: AWS Well-Architected Performance Efficiency Pillar review. Checks resource selection, scaling, caching, and monitoring configurations in IaC code.
---

# Performance Efficiency Pillar

리소스 효율, 적정 규모, 성능 모니터링 관점에서 IaC 코드를 검토합니다.

## 핵심 원칙

1. **고급 기술의 대중화**: 관리형 서비스 활용
2. **몇 분 만에 전 세계 배포**: CloudFront, Global Accelerator
3. **서버리스 아키텍처 사용**: Lambda, Fargate
4. **더 자주 실험**: A/B 테스트
5. **기계적 공감**: 워크로드에 맞는 리소스 선택

## 검토 항목

### PERF-01: 인스턴스 세대

| 심각도 | 탐지 유형 |
|--------|-----------|
| Medium | 자동 탐지 |

**검토 내용**: 구세대 인스턴스 사용 여부 확인

**구세대 인스턴스 목록**:
- t2, m4, m3, c4, c3, r4, r3, i2, d2

**Terraform 패턴**:
```hcl
# 취약 - 구세대 인스턴스
resource "aws_instance" "bad" {
  instance_type = "t2.micro"
}

# 안전 - 현세대 인스턴스
resource "aws_instance" "good" {
  instance_type = "t3.micro"
}
```

### PERF-02: Graviton 인스턴스

| 심각도 | 탐지 유형 |
|--------|-----------|
| Low | 자동 탐지 |

**검토 내용**: ARM 기반 Graviton 인스턴스 사용 권장

**Graviton 인스턴스**:
- t4g, m6g, m7g, c6g, c7g, r6g, r7g

**Terraform 패턴**:
```hcl
# 권장 - Graviton 인스턴스 (비용 효율적, 에너지 효율적)
resource "aws_instance" "good" {
  instance_type = "t4g.micro"
}
```

### PERF-03: 캐싱 레이어

| 심각도 | 탐지 유형 |
|--------|-----------|
| Medium | 자동 탐지 |

**검토 내용**: ElastiCache, CloudFront 등 캐싱 레이어 존재 여부 확인

**Terraform 패턴**:
```hcl
# 권장 - ElastiCache 사용
resource "aws_elasticache_cluster" "redis" {
  cluster_id           = "my-cache"
  engine               = "redis"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
}

# 권장 - CloudFront 사용
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  # ...
}
```

### PERF-04: RDS 성능 설정

| 심각도 | 탐지 유형 |
|--------|-----------|
| Medium | 자동 탐지 |

**검토 내용**: RDS 인스턴스 크기, IOPS 설정 확인

**Terraform 패턴**:
```hcl
# 고성능 요구 시 - Provisioned IOPS
resource "aws_db_instance" "high_perf" {
  instance_class    = "db.r5.large"
  storage_type      = "io1"
  iops              = 3000
  allocated_storage = 100
}
```

### PERF-05: Lambda 설정

| 심각도 | 탐지 유형 |
|--------|-----------|
| Medium | 자동 탐지 |

**검토 내용**: Lambda 메모리, 타임아웃 적정성 확인

**Terraform 패턴**:
```hcl
# 검토 필요 - 과도한 타임아웃
resource "aws_lambda_function" "review" {
  memory_size = 128
  timeout     = 900  # 15분 - 정말 필요한가?
}

# 권장 - 적절한 설정
resource "aws_lambda_function" "good" {
  memory_size = 256
  timeout     = 30
}
```

### PERF-06: EBS 볼륨 타입

| 심각도 | 탐지 유형 |
|--------|-----------|
| Low | 자동 탐지 |

**검토 내용**: 워크로드에 적합한 EBS 볼륨 타입 사용 여부

**볼륨 타입 권장**:
- 범용: gp3 (gp2보다 비용 효율적)
- 고성능: io2
- 처리량 최적화: st1

### PERF-07: 성능 모니터링

| 심각도 | 탐지 유형 |
|--------|-----------|
| Medium | 자동 탐지 |

**검토 내용**: Enhanced Monitoring, Performance Insights 활성화 여부

**Terraform 패턴**:
```hcl
# 권장 - Performance Insights 활성화
resource "aws_db_instance" "good" {
  performance_insights_enabled = true
  monitoring_interval          = 60  # Enhanced Monitoring
  monitoring_role_arn          = aws_iam_role.rds_monitoring.arn
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
| 인스턴스 세대 | 20% |
| Graviton 사용 | 10% |
| 캐싱 레이어 | 25% |
| RDS 성능 | 20% |
| Lambda 설정 | 15% |
| 성능 모니터링 | 10% |
