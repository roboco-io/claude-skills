# Issue #2: AWS Well-Architected Review 스킬 작업 계획

## 개요

AWS Well-Architected Framework 기반의 `aws-well-architected` 스킬을 개발하여 클라우드 워크로드의 아키텍처를 자동으로 검토합니다.

## 참고 자료

- [AWS Well-Architected Framework (2024-06-27)](https://docs.aws.amazon.com/pdfs/wellarchitected/2024-06-27/framework/wellarchitected-framework-2024-06-27.pdf)
- [The Pillars of the Framework](https://docs.aws.amazon.com/wellarchitected/latest/framework/the-pillars-of-the-framework.html)
- [Operational Excellence Pillar](https://docs.aws.amazon.com/wellarchitected/latest/operational-excellence-pillar/welcome.html)
- [Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [Reliability Pillar](https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/welcome.html)
- [Performance Efficiency Pillar](https://docs.aws.amazon.com/wellarchitected/latest/performance-efficiency-pillar/welcome.html)
- [Cost Optimization Pillar](https://docs.aws.amazon.com/wellarchitected/latest/cost-optimization-pillar/welcome.html)
- [Sustainability Pillar](https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sustainability-pillar.html)

---

## Well-Architected Framework 6 Pillars

| Pillar | 설명 | 심각도 |
|--------|------|--------|
| Operational Excellence | 운영 효율성, 모니터링, 지속적 개선 | High |
| Security | 데이터 보호, ID/접근 관리, 탐지 제어 | Critical |
| Reliability | 장애 복구, 확장성, 고가용성 | Critical |
| Performance Efficiency | 리소스 효율, 적정 규모, 성능 모니터링 | High |
| Cost Optimization | 비용 최적화, 탄력성, 구매 옵션 | Medium |
| Sustainability | 환경 영향 최소화, 에너지 효율 | Medium |

---

## 작업 단계

### Phase 1: 기반 구조 설계

#### 1.1 스킬 구조 정의
```
plugins/security/skills/aws-well-architected/
├── SKILL.md                    # 메인 스킬 정의
└── references/
    ├── pillars/
    │   ├── operational-excellence.md
    │   ├── security.md
    │   ├── reliability.md
    │   ├── performance-efficiency.md
    │   ├── cost-optimization.md
    │   └── sustainability.md
    └── checklists/
        ├── terraform.md        # Terraform 리뷰 체크리스트
        ├── cloudformation.md   # CloudFormation 리뷰 체크리스트
        └── cdk.md              # AWS CDK 리뷰 체크리스트
```

#### 1.2 리뷰 출력 형식 설계

```markdown
## AWS Well-Architected Review Report

### Summary
| Pillar | Score | High Risk | Medium Risk |
|--------|-------|-----------|-------------|
| Operational Excellence | 3/5 | 1 | 2 |
| Security | 2/5 | 3 | 1 |
| Reliability | 4/5 | 0 | 2 |
| Performance Efficiency | 3/5 | 1 | 1 |
| Cost Optimization | 2/5 | 2 | 3 |
| Sustainability | 3/5 | 0 | 1 |

### High Risk Findings

#### [CRITICAL] SEC-01: Unencrypted S3 Bucket
- **Pillar**: Security
- **Resource**: `aws_s3_bucket.data_bucket`
- **Location**: `infrastructure/storage.tf:15`
- **Risk**: 데이터가 암호화되지 않아 유출 시 평문 노출
- **Recommendation**:
```hcl
resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.data_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
```
```


---

### Phase 2: 각 Pillar별 상세 분석

#### 2.1 Operational Excellence

**핵심 질문:**
- 워크로드 운영에 대한 종합적 이해가 있는가?
- 배포 및 인시던트 대응 자동화가 되어있는가?
- 지속적 개선 프로세스가 있는가?

**자동 검토 항목:**
| 항목 | 검토 방법 | 심각도 |
|------|-----------|--------|
| CloudWatch 설정 | 로그 그룹, 알람, 대시보드 존재 여부 | High |
| X-Ray 트레이싱 | 트레이싱 활성화 여부 | Medium |
| CI/CD 파이프라인 | CodePipeline/GitHub Actions 설정 | Medium |
| 런북/플레이북 | 문서 존재 여부 (수동 확인 필요) | Low |

**Anti-Pattern 탐지:**
- CloudWatch 로그 그룹 없음
- 알람 미설정
- 수동 배포 의존

#### 2.2 Security

**핵심 질문:**
- ID 및 접근 관리가 적절한가?
- 데이터 보호 (암호화)가 구현되었는가?
- 탐지 제어가 활성화되어있는가?

**자동 검토 항목:**
| 항목 | 검토 방법 | 심각도 |
|------|-----------|--------|
| IAM 최소 권한 | `*` 와일드카드, 과도한 권한 탐지 | Critical |
| S3 암호화 | 서버 측 암호화 설정 확인 | Critical |
| RDS 암호화 | storage_encrypted 설정 | Critical |
| VPC Flow Logs | 플로우 로그 활성화 여부 | High |
| GuardDuty | 탐지 서비스 활성화 | High |
| Security Groups | 0.0.0.0/0 인바운드 규칙 | Critical |
| KMS 키 관리 | CMK 사용, 키 로테이션 | High |

**Anti-Pattern 탐지:**
- `"Action": "*"` 또는 `"Resource": "*"` IAM 정책
- 퍼블릭 S3 버킷
- 암호화되지 않은 EBS 볼륨
- 기본 VPC 사용
- Security Group에 0.0.0.0/0 SSH/RDP 허용

#### 2.3 Reliability

**핵심 질문:**
- 복구 절차가 테스트되었는가?
- 컴포넌트 장애를 견딜 수 있는가?
- 수평 확장이 가능한가?

**자동 검토 항목:**
| 항목 | 검토 방법 | 심각도 |
|------|-----------|--------|
| Multi-AZ 배포 | AZ 분산 설정 확인 | Critical |
| Auto Scaling | ASG 설정, 최소/최대 인스턴스 | High |
| RDS Multi-AZ | multi_az 설정 | High |
| S3 복제 | Cross-Region Replication | Medium |
| 백업 설정 | 자동 백업, 보존 기간 | High |
| Health Check | ALB 헬스체크 설정 | High |

**Anti-Pattern 탐지:**
- 단일 AZ 배포
- Auto Scaling 미설정
- 백업 미설정 또는 짧은 보존 기간
- 단일 NAT Gateway

#### 2.4 Performance Efficiency

**핵심 질문:**
- 적절한 리소스 유형을 사용하는가?
- 병목 지점을 모니터링하는가?
- 캐싱, 엣지 컴퓨팅을 활용하는가?

**자동 검토 항목:**
| 항목 | 검토 방법 | 심각도 |
|------|-----------|--------|
| 인스턴스 타입 | 구세대 인스턴스 사용 여부 | Medium |
| Graviton 사용 | ARM 기반 인스턴스 권장 | Low |
| 캐싱 레이어 | ElastiCache, CloudFront 존재 | Medium |
| RDS 성능 | 프로비저닝된 IOPS, 인스턴스 크기 | Medium |
| Lambda 설정 | 메모리, 타임아웃 적정성 | Medium |

**Anti-Pattern 탐지:**
- 구세대 인스턴스 (m4, t2 등)
- 캐싱 없는 고트래픽 워크로드
- 과도한 Lambda 타임아웃

#### 2.5 Cost Optimization

**핵심 질문:**
- 리소스를 적정 규모로 사용하는가?
- 탄력적 스케일링을 활용하는가?
- 비용 절감 구매 옵션을 사용하는가?

**자동 검토 항목:**
| 항목 | 검토 방법 | 심각도 |
|------|-----------|--------|
| 인스턴스 크기 | 과도한 스펙 여부 | Medium |
| Reserved/Savings | 예약 인스턴스 사용 여부 (수동 확인) | Medium |
| S3 스토리지 클래스 | Intelligent-Tiering, Glacier 활용 | Low |
| 유휴 리소스 | 미사용 EIP, 볼륨 탐지 | Medium |
| 데이터 전송 | 리전 간 전송 최적화 | Medium |

**Anti-Pattern 탐지:**
- 항상 실행되는 개발/테스트 환경
- 미사용 리소스 (EIP, 스냅샷, 볼륨)
- 모든 데이터를 S3 Standard에 저장

#### 2.6 Sustainability

**핵심 질문:**
- 에너지 효율적인 리소스를 선택하는가?
- 공유 인프라를 활용하는가?
- 미사용 리소스를 정리하는가?

**자동 검토 항목:**
| 항목 | 검토 방법 | 심각도 |
|------|-----------|--------|
| Graviton 인스턴스 | 에너지 효율 인스턴스 사용 | Low |
| Serverless 활용 | Lambda, Fargate 사용 여부 | Low |
| 관리형 서비스 | RDS, ElastiCache 등 활용 | Low |
| 리전 선택 | 저탄소 리전 선택 | Low |

**Anti-Pattern 탐지:**
- 과도한 크기의 인스턴스
- 미사용 리소스 방치
- Serverless 대신 항상 실행 인스턴스

---

### Phase 3: IaC 플랫폼별 탐지 패턴

#### 3.1 Terraform

| Pillar | 취약 패턴 | 안전한 패턴 |
|--------|-----------|-------------|
| Security | `acl = "public-read"` | `acl = "private"` |
| Security | `encrypted = false` | `encrypted = true` |
| Security | `cidr_blocks = ["0.0.0.0/0"]` (SSH) | 특정 IP 대역 |
| Security | `"Action": "*"` | 최소 권한 Action |
| Reliability | `multi_az = false` | `multi_az = true` |
| Reliability | 단일 `availability_zone` | 다중 AZ 분산 |
| Cost | `instance_type = "m5.4xlarge"` (항상) | 적정 크기 + Auto Scaling |
| Performance | `instance_type = "t2.micro"` | 현세대 인스턴스 |

#### 3.2 CloudFormation

| Pillar | 취약 패턴 | 안전한 패턴 |
|--------|-----------|-------------|
| Security | `AccessControl: PublicRead` | `AccessControl: Private` |
| Security | `StorageEncrypted: false` | `StorageEncrypted: true` |
| Reliability | `MultiAZ: false` | `MultiAZ: true` |
| Reliability | 단일 AZ Subnet 참조 | 다중 AZ Subnet |

#### 3.3 AWS CDK (TypeScript)

| Pillar | 취약 패턴 | 안전한 패턴 |
|--------|-----------|-------------|
| Security | `publicReadAccess: true` | `publicReadAccess: false` |
| Security | `encryption: BucketEncryption.UNENCRYPTED` | `BucketEncryption.S3_MANAGED` |
| Reliability | `multiAz: false` | `multiAz: true` |

---

### Phase 4: 인터뷰 기반 컨텍스트 수집

리포지토리만으로 판단이 어려운 경우 AskUserQuestion을 통해 추가 정보를 수집합니다.

#### 4.1 인터뷰 질문 목록

**Operational Excellence:**
- 배포 파이프라인은 어떤 도구를 사용하나요? (CodePipeline, GitHub Actions, Jenkins 등)
- 인시던트 대응 프로세스가 문서화되어 있나요?
- 런북/플레이북이 존재하나요?

**Security:**
- 데이터 분류 정책이 있나요? (민감 데이터 식별)
- 규정 준수 요구사항이 있나요? (HIPAA, PCI-DSS, GDPR 등)
- 침투 테스트를 정기적으로 수행하나요?

**Reliability:**
- RTO (복구 시간 목표)와 RPO (복구 지점 목표)가 정의되어 있나요?
- 재해 복구 계획이 있나요? 테스트되었나요?
- 예상 트래픽 패턴은 어떤가요? (피크 타임, 계절성)

**Performance Efficiency:**
- 현재 성능 병목 지점이 있나요?
- 예상 동시 사용자 수는?
- 지연 시간 요구사항이 있나요?

**Cost Optimization:**
- 월간 AWS 예산이 있나요?
- Reserved Instance나 Savings Plan을 사용하고 있나요?
- 비용 알림이 설정되어 있나요?

**Sustainability:**
- 지속 가능성 목표가 있나요?
- 탄소 발자국 추적을 하고 있나요?

#### 4.2 인터뷰 트리거 조건

다음 상황에서 자동으로 인터뷰 시작:
1. IaC 파일이 없거나 불완전한 경우
2. 규정 준수 관련 리소스 발견 시
3. 복구/백업 설정이 모호한 경우
4. 비용 최적화 판단에 추가 정보 필요 시

---

### Phase 5: SKILL.md 작성

#### 5.1 구조
1. YAML frontmatter (name, description)
2. 스킬 목적 및 사용 시점
3. 리뷰 프로세스 가이드
4. 6 Pillars 체크리스트 요약
5. IaC 플랫폼별 탐지 패턴
6. 인터뷰 질문 가이드
7. 출력 형식 템플릿
8. 심각도 분류 기준

#### 5.2 핵심 기능
- IaC 코드 리뷰 시 자동 Well-Architected 관점 적용
- 각 Pillar별 구체적 탐지 패턴 제공
- 발견된 리스크에 대한 수정 가이드 제공
- 컨텍스트 부족 시 자동 인터뷰 진행
- Pillar별 점수 및 리스크 요약 제공

---

### Phase 6: 테스트 및 검증

#### 6.1 테스트 케이스
각 Pillar별 취약한 IaC 샘플로 테스트:
- Terraform: AWS Provider 기반 인프라
- CloudFormation: YAML/JSON 템플릿
- CDK: TypeScript 애플리케이션

#### 6.2 검증 항목
- [ ] 각 Pillar 리스크 탐지 여부
- [ ] 오탐(False Positive) 비율
- [ ] 수정 제안의 정확성
- [ ] 인터뷰 질문의 적절성
- [ ] 출력 형식 일관성

---

### Phase 7: 문서화 및 배포

#### 7.1 README 업데이트
- 새 스킬 목록에 추가
- 사용 예시 추가

#### 7.2 커밋 및 PR
```
feat(security): add aws-well-architected review skill

- Add comprehensive Well-Architected review skill
- Support Terraform, CloudFormation, AWS CDK
- Include detection patterns for all 6 pillars
- Provide fix recommendations with code examples
- Auto-interview for missing context

Closes #2
```

---

## 일정 (작업 순서)

1. **Phase 1**: 기반 구조 설계
2. **Phase 2**: 각 Pillar별 상세 분석 (이 문서에서 완료)
3. **Phase 3**: IaC 플랫폼별 패턴 정의 (이 문서에서 완료)
4. **Phase 4**: 인터뷰 질문 정의 (이 문서에서 완료)
5. **Phase 5**: SKILL.md 작성
6. **Phase 6**: 테스트 및 검증
7. **Phase 7**: 문서화 및 배포

---

## 산출물

| 파일 | 설명 |
|------|------|
| `plugins/security/skills/aws-well-architected/SKILL.md` | 메인 스킬 정의 |
| `plugins/security/skills/aws-well-architected/references/pillars/*.md` | Pillar별 상세 체크리스트 |
| `plugins/security/skills/aws-well-architected/references/checklists/*.md` | IaC 플랫폼별 체크리스트 |
| `README.md` (업데이트) | 스킬 목록에 추가 |
| 이슈 #2 종료 | PR 머지 후 자동 종료 |
