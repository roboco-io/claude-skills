# Issue #2: AWS Well-Architected Review 스킬 스펙 문서

## 1. 개요

### 1.1 목적
AWS Well-Architected Framework 기반의 IaC 코드 리뷰 스킬을 개발하여 클라우드 워크로드의 아키텍처를 자동으로 검토합니다.

### 1.2 핵심 가치
- **자동화된 아키텍처 리뷰**: IaC 코드 분석을 통한 Well-Architected 원칙 준수 여부 자동 검토
- **컨텍스트 기반 분석**: 부족한 정보는 인터뷰를 통해 보완
- **지속적 개선 추적**: 히스토리 비교를 통한 개선/악화 트렌드 파악
- **팀 협업 지원**: 발견 사항에 대한 담당자 할당 및 이슈 연동

---

## 2. 아키텍처

### 2.1 스킬 구조 (Pillar별 분리)

```
plugins/security/skills/
├── aws-well-architected/           # 메인 오케스트레이터 스킬
│   ├── SKILL.md
│   └── references/
│       ├── overview.md             # Framework 개요
│       └── compliance-mapping.md   # Compliance 매핑 테이블
│
├── aws-wa-operational-excellence/  # Operational Excellence Pillar
│   ├── SKILL.md
│   └── references/
│       ├── checklist.md
│       └── patterns/
│           ├── terraform.md
│           ├── cloudformation.md
│           ├── cdk.md
│           └── pulumi.md
│
├── aws-wa-security/                # Security Pillar
│   ├── SKILL.md                    # owasp-review 연동
│   └── references/
│       ├── checklist.md
│       └── patterns/
│           └── ...
│
├── aws-wa-reliability/             # Reliability Pillar
│   ├── SKILL.md
│   └── references/
│       └── ...
│
├── aws-wa-performance/             # Performance Efficiency Pillar
│   ├── SKILL.md
│   └── references/
│       └── ...
│
├── aws-wa-cost/                    # Cost Optimization Pillar
│   ├── SKILL.md
│   └── references/
│       └── ...
│
└── aws-wa-sustainability/          # Sustainability Pillar
    ├── SKILL.md
    └── references/
        └── ...
```

### 2.2 메인 스킬 역할 (aws-well-architected)

1. **오케스트레이터**: 사용자 입력 받고 적절한 Pillar 스킬 호출
2. **요약 리포터**: Pillar별 리뷰 결과를 통합하여 요약 리포트 생성
3. **인터뷰 진행자**: 컨텍스트 부족 시 인터뷰 질문 진행
4. **히스토리 관리자**: 이전 리뷰 결과와 비교 분석

---

## 3. 기능 스펙

### 3.1 리뷰 트리거

| 트리거 | 설명 | 설정 |
|--------|------|------|
| 수동 요청 | `/aws-wa-review` 명령어 | 항상 가능 |
| 자동 실행 | IaC 파일 변경 감지 시 | 사용자 설정 가능 |
| 특정 디렉토리 | infrastructure/, cdk/ 등 | 사용자 설정 가능 |

**설정 방식**: 프로젝트 루트의 `.wa-config.yaml` 또는 인터뷰로 설정

```yaml
# .wa-config.yaml 예시
trigger:
  auto: true
  paths:
    - "infrastructure/**/*.tf"
    - "cdk/**/*.ts"
    - "cloudformation/**/*.yaml"
```

### 3.2 리뷰 범위

| 옵션 | 설명 |
|------|------|
| 전체 리포지토리 | 모든 IaC 파일 스캔 |
| 변경된 파일만 | git diff 기준 변경된 파일만 |
| 지정 디렉토리 | 사용자가 지정한 경로만 |

**기본값**: 유연하게 선택 (파라미터로 지정)

### 3.3 Pillar 선택

- **기본**: 사용자가 리뷰할 Pillar 선택
- **전체 리뷰**: 6개 Pillar 모두 리뷰
- **빠른 리뷰**: Security + Reliability만 리뷰

```
사용자: "인프라 코드 리뷰해줘"
Claude: "어떤 Pillar를 리뷰할까요?"
  1. 전체 6 Pillars (권장)
  2. Security + Reliability만
  3. 직접 선택
```

### 3.4 단계별 리뷰 (범위가 넓을 경우)

1. **1단계**: Critical 리스크만 빠르게 스캔
2. **2단계**: High 리스크 추가 분석
3. **3단계**: Medium/Low 포함 전체 분석

---

## 4. 지원 IaC 플랫폼

### 4.1 지원 범위

| 플랫폼 | 지원 수준 | 파일 확장자 |
|--------|-----------|-------------|
| Terraform | Full | `.tf`, `.tfvars` |
| CloudFormation | Full | `.yaml`, `.yml`, `.json` (CFn) |
| AWS CDK | Full | `.ts`, `.py`, `.java` (CDK) |
| Pulumi | Full | `.ts`, `.py`, `.go`, `.yaml` |

### 4.2 확장성

- 멀티 클라우드 확장 가능한 구조로 설계
- 향후 GCP/Azure Well-Architected Framework 지원 고려

---

## 5. 탐지 메커니즘

### 5.1 오탐(False Positive) 전략

| 심각도 | 전략 | 설명 |
|--------|------|------|
| Critical | 엄격 | 확실한 것만 탐지, 오탐 최소화 |
| High | 엄격 | 확실한 것만 탐지 |
| Medium | 보통 | 적절한 균형 |
| Low | 넓음 | 의심스러운 것도 탐지, 오탐 감수 |

### 5.2 탐지 구분 표시

모든 발견 사항에 라벨 표시:
- `[자동 탐지]`: IaC 코드에서 자동으로 탐지된 항목
- `[수동 확인 필요]`: 코드만으로 판단 불가, 수동 확인 필요

### 5.3 AWS API 호출 (선택적)

- **기본**: IaC 코드 정적 분석만
- **옵션**: AWS API 호출로 실제 리소스 상태 확인
  - AWS 자격 증명 필요
  - 읽기 전용 API만 호출

---

## 6. 인터뷰 시스템

### 6.1 트리거 조건

다음 상황에서 인터뷰 여부 확인 후 진행:
1. IaC 파일이 없거나 불완전한 경우
2. 규정 준수 관련 리소스 발견 시
3. 복구/백업 설정이 모호한 경우
4. 비용 최적화 판단에 추가 정보 필요 시

### 6.2 인터뷰 진행 방식

```
Claude: "컨텍스트가 부족합니다. 더 정확한 리뷰를 위해 몇 가지 질문을 드려도 될까요?"
  1. 예, 인터뷰 진행
  2. 아니오, 확인 가능한 범위만 리뷰
```

### 6.3 질문 범위 (비즈니스 컨텍스트 포함)

**기술적 질문:**
- RTO/RPO 정의 여부
- 트래픽 패턴 (피크 타임, 계절성)
- 성능 요구사항 (지연 시간, 동시 사용자)

**비즈니스 질문:**
- 규정 준수 요구사항 (HIPAA, PCI-DSS, GDPR 등)
- 월간 AWS 예산
- 데이터 분류 정책

### 6.4 질문 응답 방식

- **객관식 선택**: AskUserQuestion으로 선택지 제공
- 질문당 2-4개 선택지 + "기타" 옵션

---

## 7. 출력 형식

### 7.1 리포트 언어

- 사용자 선택 가능 (한국어/영어)
- 기본값: 시스템 설정 또는 첫 인터뷰에서 확인

### 7.2 리포트 구조 (상세 리포트)

```markdown
# AWS Well-Architected Review Report

**리뷰 일시**: 2026-01-19 10:30:00
**리뷰 범위**: infrastructure/ (Terraform)
**Framework 버전**: 2024-06-27

## Executive Summary

| Pillar | Score | Critical | High | Medium | Low | 변화 |
|--------|-------|----------|------|--------|-----|------|
| Operational Excellence | 3/5 | 0 | 1 | 2 | 1 | ↑ |
| Security | 2/5 | 2 | 1 | 1 | 0 | ↓ |
| Reliability | 4/5 | 0 | 0 | 2 | 1 | → |
| Performance Efficiency | 3/5 | 0 | 1 | 1 | 2 | ↑ |
| Cost Optimization | 2/5 | 1 | 1 | 3 | 0 | → |
| Sustainability | 4/5 | 0 | 0 | 1 | 2 | ↑ |

**전체 점수**: 3.0/5 (이전 대비 +0.3)

---

## Critical Findings

### [CRITICAL] SEC-01: Unencrypted S3 Bucket
- **Pillar**: Security
- **탐지 유형**: [자동 탐지]
- **Resource**: `aws_s3_bucket.data_bucket`
- **Location**: `infrastructure/storage.tf:15`
- **Compliance**: PCI-DSS 3.4, HIPAA §164.312(a)(2)(iv)
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
- **담당자**: (미할당)
- **상태**: Open

---

## High Risk Findings
...

## Medium Risk Findings
...

## Low Risk Findings
...

---

## Manual Review Checklist

다음 항목은 코드만으로 판단이 어려워 수동 확인이 필요합니다:

- [ ] **OPS-01**: 런북/플레이북 문서 존재 여부 확인
- [ ] **REL-01**: 재해 복구 계획 테스트 여부 확인
- [ ] **COST-01**: Reserved Instance 사용 현황 확인

---

## Compliance Summary

| Framework | 관련 항목 | 준수 | 미준수 |
|-----------|-----------|------|--------|
| PCI-DSS | 5 | 3 | 2 |
| HIPAA | 3 | 1 | 2 |
| SOC2 | 4 | 4 | 0 |

---

## 히스토리 비교

**이전 리뷰**: 2026-01-12

| 변화 | 항목 |
|------|------|
| 개선됨 | OPS-02: CloudWatch 알람 설정 추가 |
| 악화됨 | SEC-01: 새 S3 버킷 암호화 미설정 |
| 신규 | COST-03: 구세대 인스턴스 사용 |
```

### 7.3 점수 시스템

- **5점 척도**: 1-5점 (AWS 공식 방식 유사)
- 각 Pillar별 점수 + 전체 평균 점수
- 리스크 개수 병행 표시

### 7.4 권장사항 수준

- 문제점 설명
- 수정된 코드 예시 (IaC 플랫폼별)
- 관련 Compliance 매핑
- AWS 공식 문서 링크 (필요 시)

---

## 8. 파일 저장

### 8.1 저장 경로

```
docs/wa-reviews/
├── 2026-01-19-103000.md    # 리뷰 결과 (타임스탬프)
├── 2026-01-12-143000.md    # 이전 리뷰
├── history.json            # 히스토리 메타데이터
└── config.yaml             # 리뷰 설정
```

### 8.2 히스토리 메타데이터

```json
{
  "reviews": [
    {
      "date": "2026-01-19T10:30:00",
      "file": "2026-01-19-103000.md",
      "scores": {
        "operational_excellence": 3,
        "security": 2,
        "reliability": 4,
        "performance_efficiency": 3,
        "cost_optimization": 2,
        "sustainability": 4
      },
      "total_findings": {
        "critical": 3,
        "high": 4,
        "medium": 10,
        "low": 6
      }
    }
  ]
}
```

---

## 9. 협업 기능

### 9.1 파일 기반 추적 (기본)

리뷰 결과 파일에 담당자/상태 필드 추가:
```markdown
- **담당자**: @username
- **상태**: Open | In Progress | Resolved | Won't Fix
```

### 9.2 GitHub Issue 연동 (선택적)

발견 사항을 GitHub Issue로 자동 생성 옵션:
```
Claude: "발견된 Critical 항목을 GitHub Issue로 생성할까요?"
  1. 예, Issue 생성
  2. 아니오, 파일만 저장
```

Issue 생성 시:
- Title: `[WA-SEC-01] Unencrypted S3 Bucket`
- Labels: `well-architected`, `security`, `critical`
- Body: 리포트의 해당 섹션 내용

---

## 10. 히스토리 추적

### 10.1 구현 방식

- **파일 기반 비교**: `docs/wa-reviews/` 내 이전 리뷰 파일과 비교
- **history.json**: 점수 및 발견 사항 메타데이터 저장

### 10.2 트렌드 표시

| 기호 | 의미 |
|------|------|
| ↑ | 개선됨 (점수 상승) |
| ↓ | 악화됨 (점수 하락) |
| → | 변화 없음 |
| 🆕 | 신규 발견 항목 |
| ✅ | 해결된 항목 |

---

## 11. Compliance 매핑

### 11.1 지원 프레임워크

| Framework | 설명 |
|-----------|------|
| PCI-DSS | 결제 카드 산업 데이터 보안 표준 |
| HIPAA | 미국 의료정보 보호법 |
| SOC2 | 서비스 조직 통제 |
| GDPR | EU 일반 데이터 보호 규정 |
| ISO 27001 | 정보보안 관리 체계 |

### 11.2 매핑 방식

각 Well-Architected 체크 항목에 관련 Compliance 요구사항 매핑:
```markdown
| WA 항목 | PCI-DSS | HIPAA | SOC2 |
|---------|---------|-------|------|
| 데이터 암호화 | 3.4 | §164.312(a)(2)(iv) | CC6.1 |
| 접근 제어 | 7.1 | §164.312(a)(1) | CC6.3 |
```

---

## 12. owasp-review 연동

### 12.1 연동 방식

Security Pillar 리뷰 시 owasp-review 스킬 참조:
- 애플리케이션 코드가 있는 경우 owasp-review도 함께 실행 제안
- Security Pillar 결과에 OWASP 관련 항목 포함

### 12.2 연동 범위

```
Claude: "Security Pillar 리뷰 중입니다.
         애플리케이션 코드(src/)도 발견되었습니다.
         OWASP 보안 리뷰도 함께 수행할까요?"
  1. 예, OWASP 리뷰도 수행
  2. 아니오, IaC만 리뷰
```

---

## 13. CI/CD 통합

### 13.1 GitHub Actions 연동

```yaml
# .github/workflows/wa-review.yml
name: Well-Architected Review
on:
  pull_request:
    paths:
      - 'infrastructure/**'
      - 'cdk/**'

jobs:
  wa-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Well-Architected Review
        run: |
          # Claude Code CLI로 리뷰 실행
          claude-code --skill aws-well-architected --output docs/wa-reviews/
```

### 13.2 PR 코멘트

리뷰 결과 요약을 PR 코멘트로 자동 추가 (선택적)

---

## 14. 대시보드 (마크다운)

### 14.1 대시보드 파일

`docs/wa-reviews/DASHBOARD.md` 자동 생성:

```markdown
# Well-Architected Dashboard

**최근 업데이트**: 2026-01-19

## 점수 트렌드

| 날짜 | OPS | SEC | REL | PERF | COST | SUS | 평균 |
|------|-----|-----|-----|------|------|-----|------|
| 01-19 | 3 | 2 | 4 | 3 | 2 | 4 | 3.0 |
| 01-12 | 2 | 3 | 4 | 2 | 2 | 3 | 2.7 |
| 01-05 | 2 | 2 | 3 | 2 | 2 | 3 | 2.3 |

## Open Items

| 심각도 | Pillar | 항목 | 담당자 | 생성일 |
|--------|--------|------|--------|--------|
| Critical | Security | SEC-01 | - | 01-19 |
| Critical | Cost | COST-01 | @user1 | 01-12 |
| High | OPS | OPS-02 | @user2 | 01-05 |

## 최근 해결된 항목

- ✅ OPS-01: CloudWatch 설정 (01-19)
- ✅ REL-02: Multi-AZ 설정 (01-15)
```

---

## 15. 버전 관리

### 15.1 Framework 버전 추적

- 현재 지원: AWS Well-Architected Framework 2024-06-27
- AWS 문서 버전 변경 시 스킬 업데이트

### 15.2 업데이트 알림

리뷰 시 Framework 버전 변경 감지:
```
Claude: "AWS Well-Architected Framework가 업데이트되었습니다.
         (2024-06-27 → 2025-XX-XX)
         새 버전 기준으로 리뷰할까요?"
```

---

## 16. 산출물 목록

| 파일 | 설명 |
|------|------|
| `plugins/security/skills/aws-well-architected/SKILL.md` | 메인 스킬 |
| `plugins/security/skills/aws-wa-*/SKILL.md` | Pillar별 스킬 (6개) |
| `plugins/security/skills/aws-wa-*/references/*.md` | 참조 문서 |
| `README.md` (업데이트) | 스킬 목록에 추가 |

---

## 17. 인터뷰 요약

| 항목 | 결정 사항 |
|------|-----------|
| 사용 시나리오 | 자동 + 수동 모두 지원, 트리거 조건 설정 가능 |
| 리뷰 범위 | 유연하게 선택 (전체/변경분/지정 디렉토리) |
| Pillar 범위 | 사용자 선택 |
| 출력 형식 | 상세 리포트 |
| 점수 시스템 | 5점 척도 (1-5) |
| 권장사항 | 코드 예시 포함 |
| 인터뷰 방식 | 확인 후 진행, 객관식 선택 |
| 질문 범위 | 비즈니스 컨텍스트 포함 |
| 탐지 구분 | 자동/수동 라벨 표시 |
| IaC 지원 | Terraform, CloudFormation, CDK, Pulumi |
| 멀티 클라우드 | AWS 우선, 향후 GCP/Azure 확장 가능 |
| 오탐 전략 | 심각도별 다르게 (Critical 엄격, Low 넓음) |
| 예외 처리 | 필요 없음 |
| 성능 | 정확도 우선 |
| 리포트 언어 | 사용자 선택 |
| 자동 트리거 | 설정 가능 |
| 결과 저장 | 자동 저장 (docs/wa-reviews/) |
| 스킬 분리 | Pillar별 분리 |
| 협업 | 파일 기반 + Issue 연동 선택적 |
| 히스토리 | 파일 기반 비교 |
| MVP 범위 | 전체 6 Pillars + 4 IaC + 협업 + 히스토리 |
| Compliance | 매핑 제공 (PCI-DSS, HIPAA, SOC2 등) |
| owasp-review | Security Pillar 연동 |
| 버전 관리 | AWS 문서 버전 추적 |
| CI/CD | GitHub Actions 통합 고려 |
| 대시보드 | 마크다운으로 생성 |
| AWS API | IaC 기본, API 호출 옵션 |
