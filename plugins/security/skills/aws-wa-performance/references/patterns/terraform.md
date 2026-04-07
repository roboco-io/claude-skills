# Performance Efficiency Pillar - Terraform 패턴

## 적절한 인스턴스 유형 선택

```hcl
resource "aws_instance" "compute_optimized" {
  ami           = data.aws_ami.al2023.id
  instance_type = "c7g.large"  # Graviton3 - 비용 대비 성능 우수
}
```

## CloudFront 캐싱

```hcl
resource "aws_cloudfront_distribution" "cdn" {
  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "s3-origin"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
  }
}
```

## ElastiCache 활용

```hcl
resource "aws_elasticache_replication_group" "cache" {
  replication_group_id = "app-cache"
  engine               = "redis"
  node_type            = "cache.r7g.large"
  num_cache_clusters   = 2
  automatic_failover_enabled = true
}
```

## RDS Read Replica

```hcl
resource "aws_db_instance" "read_replica" {
  replicate_source_db = aws_db_instance.main.identifier
  instance_class      = "db.r6g.large"
}
```
