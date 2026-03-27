---
name: aws-well-architected
description: AWS Well-Architected Framework based IaC review orchestrator. Use when users request infrastructure review, cloud architecture assessment, or Well-Architected review. Supports Terraform, CloudFormation, CDK, and Pulumi.
---

# AWS Well-Architected Review Skill

AWS Well-Architected Framework 기반의 IaC 코드 리뷰를 수행합니다. 이 스킬은 오케스트레이터로서 6개 Pillar별 스킬을 호출하고 통합 리포트를 생성합니다.

## Framework Version

- **현재 지원**: AWS Well-Architected Framework 2024-06-27
- **참고**: [AWS Well-Architected Framework](https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html)

## 6 Pillars

| Pillar | 스킬 | 설명 |
|--------|------|------|
| Operational Excellence | `aws-wa-operational-excellence` | 운영 효율성, 모니터링, 지속적 개선 |
| Security | `aws-wa-security` | 데이터 보호, ID/접근 관리, 탐지 제어 |
| Reliability | `aws-wa-reliability` | 장애 복구, 확장성, 고가용성 |
| Performance Efficiency | `aws-wa-performance` | 리소스 효율, 적정 규모, 성능 모니터링 |
| Cost Optimization | `aws-wa-cost` | 비용 최적화, 탄력성, 구매 옵션 |
| Sustainability | `aws-wa-sustainability` | 환경 영향 최소화, 에너지 효율 |

## 지원 IaC 플랫폼

| 플랫폼 | 파일 확장자 |
|--------|-------------|
| Terraform | `.tf`, `.tfvars` |
| CloudFormation | `.yaml`, `.yml`, `.json` |
| AWS CDK | `.ts`, `.py`, `.java` |
| Pulumi | `.ts`, `.py`, `.go`, `.yaml` |

## 실행 프로세스

### 1. 초기 설정 확인

프로젝트 루트에서 `.wa-config.yaml` 확인:
```yaml
trigger:
  auto: true
  paths:
    - "infrastructure/**/*.tf"
    - "cdk/**/*.ts"
language: ko  # ko | en
pillars: all  # all | security,reliability | custom
```

설정 파일이 없으면 AskUserQuestion으로 설정 수집.

### 2. 리뷰 범위 결정

AskUserQuestion으로 확인:
```
"리뷰 범위를 선택해주세요."
  1. 전체 리포지토리 (권장)
  2. 변경된 파일만 (git diff)
  3. 특정 디렉토리 지정
```

### 3. Pillar 선택

AskUserQuestion으로 확인:
```
"어떤 Pillar를 리뷰할까요?"
  1. 전체 6 Pillars (권장)
  2. Security + Reliability만 (빠른 리뷰)
  3. 직접 선택
```

### 4. 컨텍스트 인터뷰 (필요 시)

IaC 코드만으로 판단 어려운 경우:
```
"더 정확한 리뷰를 위해 몇 가지 질문을 드려도 될까요?"
  1. 예, 인터뷰 진행
  2. 아니오, 확인 가능한 범위만 리뷰
```

**인터뷰 질문 예시:**
- 규정 준수 요구사항 (HIPAA, PCI-DSS, GDPR)
- RTO/RPO 정의 여부
- 월간 AWS 예산
- 트래픽 패턴

### 5. 단계별 리뷰 실행

대규모 리포지토리인 경우:
1. **1단계**: Critical 리스크만 스캔
2. **2단계**: High 리스크 추가
3. **3단계**: Medium/Low 포함 전체

### 6. Pillar별 스킬 호출

선택된 Pillar에 해당하는 스킬 참조:
- [aws-wa-operational-excellence](../aws-wa-operational-excellence/SKILL.md)
- [aws-wa-security](../aws-wa-security/SKILL.md)
- [aws-wa-reliability](../aws-wa-reliability/SKILL.md)
- [aws-wa-performance](../aws-wa-performance/SKILL.md)
- [aws-wa-cost](../aws-wa-cost/SKILL.md)
- [aws-wa-sustainability](../aws-wa-sustainability/SKILL.md)

### 7. 통합 리포트 생성

## 리포트 출력 형식

```markdown
# AWS Well-Architected Review Report

**리뷰 일시**: YYYY-MM-DD HH:MM:SS
**리뷰 범위**: {경로} ({IaC 플랫폼})
**Framework 버전**: 2024-06-27

## Executive Summary

| Pillar | Score | Critical | High | Medium | Low | 변화 |
|--------|-------|----------|------|--------|-----|------|
| Operational Excellence | X/5 | N | N | N | N | ↑↓→ |
| Security | X/5 | N | N | N | N | ↑↓→ |
| Reliability | X/5 | N | N | N | N | ↑↓→ |
| Performance Efficiency | X/5 | N | N | N | N | ↑↓→ |
| Cost Optimization | X/5 | N | N | N | N | ↑↓→ |
| Sustainability | X/5 | N | N | N | N | ↑↓→ |

**전체 점수**: X.X/5 (이전 대비 +/-X.X)

## Critical Findings
[각 발견 사항 상세]

## High Risk Findings
...

## Medium Risk Findings
...

## Low Risk Findings
...

## Manual Review Checklist
[수동 확인 필요 항목]

## Compliance Summary
[Compliance 매핑 요약]

## 히스토리 비교
[이전 리뷰 대비 변화]
```

## 발견 사항 형식

```markdown
### [{심각도}] {코드}: {제목}
- **Pillar**: {Pillar 이름}
- **탐지 유형**: [자동 탐지] | [수동 확인 필요]
- **Resource**: `{리소스 이름}`
- **Location**: `{파일:라인}`
- **Compliance**: {관련 규정}
- **Risk**: {위험 설명}
- **Recommendation**:
```{언어}
{수정 코드 예시}
```
- **담당자**: (미할당)
- **상태**: Open
```

## 점수 산정 기준

| 점수 | 기준 |
|------|------|
| 5/5 | Critical/High 없음, Medium 2개 이하 |
| 4/5 | Critical 없음, High 1개 이하 |
| 3/5 | Critical 없음, High 2-3개 |
| 2/5 | Critical 1개 또는 High 4개 이상 |
| 1/5 | Critical 2개 이상 |

## 히스토리 추적

### 저장 경로
```
docs/wa-reviews/
├── YYYY-MM-DD-HHMMSS.md  # 리뷰 결과
├── history.json           # 메타데이터
├── DASHBOARD.md           # 대시보드
└── config.yaml            # 설정
```

### 트렌드 표시
| 기호 | 의미 |
|------|------|
| ↑ | 개선됨 |
| ↓ | 악화됨 |
| → | 변화 없음 |

## 협업 기능

### GitHub Issue 연동 (선택적)
```
"발견된 Critical 항목을 GitHub Issue로 생성할까요?"
  1. 예, Issue 생성
  2. 아니오, 파일만 저장
```

Issue 생성 시:
- Title: `[WA-{코드}] {제목}`
- Labels: `well-architected`, `{pillar}`, `{severity}`

## Compliance 매핑

상세 매핑은 [compliance-mapping.md](references/compliance-mapping.md) 참조.

| Framework | 설명 |
|-----------|------|
| PCI-DSS | 결제 카드 산업 데이터 보안 표준 |
| HIPAA | 미국 의료정보 보호법 |
| SOC2 | 서비스 조직 통제 |
| GDPR | EU 일반 데이터 보호 규정 |
| ISO 27001 | 정보보안 관리 체계 |

## owasp-review 연동

Security Pillar 리뷰 시 애플리케이션 코드가 발견되면:
```
"애플리케이션 코드(src/)도 발견되었습니다.
 OWASP 보안 리뷰도 함께 수행할까요?"
  1. 예, OWASP 리뷰도 수행
  2. 아니오, IaC만 리뷰
```
