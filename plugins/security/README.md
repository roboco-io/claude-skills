# Security 플러그인 (Security)

애플리케이션 코드의 보안 취약점 검토(OWASP Top 10 2025)와 클라우드 인프라의 Well-Architected 리뷰를 한 플러그인에서 제공합니다. 오케스트레이터 + 6개 Pillar 전용 스킬의 계층 구조로 Progressive Disclosure를 실현합니다.

## 특징

- **OWASP Top 10 2025 커버리지** — `owasp-review`가 2025년 공식 판을 반영하여 JavaScript/TypeScript·Python·Java·Go 코드를 점검합니다.
- **AWS Well-Architected 6 Pillar 전담 스킬** — `aws-well-architected` 오케스트레이터가 Operational Excellence / Security / Reliability / Performance / Cost / Sustainability 각각의 전용 하위 스킬을 호출하여 통합 리포트를 생성합니다.
- **IaC 정적 분석** — Terraform·CloudFormation·CDK·Pulumi 파일을 직접 스캔하여 구성 오류와 미스컨피그를 찾아냅니다.
- **Compliance 매핑 내장** — PCI-DSS·HIPAA·SOC2·GDPR·ISO 27001 매핑이 권장사항에 연동되어 audit 대응에 활용 가능합니다.
- **오케스트레이터 패턴** — 필요한 Pillar만 개별 호출하거나 오케스트레이터로 전체를 묶어 실행할 수 있습니다.

## 수록 스킬

| 스킬 | 용도 | 트리거 예시 |
|------|------|-------------|
| [owasp-review](skills/owasp-review) | OWASP Top 10 2025 기반 보안 취약점 리뷰 (JS/TS, Python, Java, Go) | "이 코드 보안 리뷰해줘", "취약점 분석해줘" |
| [aws-well-architected](skills/aws-well-architected) | 6개 Pillar 하위 스킬을 호출하는 Well-Architected 리뷰 오케스트레이터 | "인프라 코드 Well-Architected 리뷰해줘", "IaC 점검해줘" |
| [aws-wa-operational-excellence](skills/aws-wa-operational-excellence) | 운영 효율성 Pillar — 모니터링·로깅·배포 자동화 점검 | "운영 효율성 Pillar만 보고 싶어" |
| [aws-wa-security](skills/aws-wa-security) | 보안 Pillar — IAM·암호화·네트워크 보안·탐지 제어 점검 | "IaC 보안 설정 점검해줘" |
| [aws-wa-reliability](skills/aws-wa-reliability) | 안정성 Pillar — HA·내결함성·백업·DR 구성 점검 | "고가용성 구성 리뷰해줘" |
| [aws-wa-performance](skills/aws-wa-performance) | 성능 효율성 Pillar — 리소스 선택·스케일링·캐싱 점검 | "성능 효율성 관점에서 리뷰" |
| [aws-wa-cost](skills/aws-wa-cost) | 비용 최적화 Pillar — 리소스 사이징·스토리지 클래스·비용 모니터링 점검 | "AWS 비용 최적화 리뷰해줘" |
| [aws-wa-sustainability](skills/aws-wa-sustainability) | 지속 가능성 Pillar — 에너지 효율·리소스 최적화 점검 | "지속 가능성 Pillar 점검" |

## 사용 예시

### 예시 1 — PR 전 애플리케이션 보안 리뷰
`owasp-review`로 인증·권한·입력 검증·시크릿 노출 등 Top 10 항목을 체크리스트로 훑어 critical/high 이슈를 PR 코멘트에 반영합니다.

### 예시 2 — 분기별 AWS 인프라 Well-Architected 점검
IaC 저장소를 기준으로 `aws-well-architected` 오케스트레이터를 실행하면 6개 Pillar별 점수·권장사항·우선순위 개선안이 담긴 통합 리포트가 생성됩니다. 다음 분기에 다시 실행하여 히스토리를 추적하세요.

### 예시 3 — Compliance audit 준비
`owasp-review`의 카테고리 매핑과 `aws-wa-security`의 IAM·암호화·로깅 권장사항을 조합하면 ISO 27001·SOC2 근거 자료로 사용할 수 있는 출력이 나옵니다.

## 설치

```bash
/plugin marketplace add roboco-io/plugins
/plugin install security@roboco-plugins
```

## 요구사항

- IaC 대상 파일(Terraform/CloudFormation/CDK/Pulumi)은 저장소 내에 평문으로 존재해야 합니다.
- Compliance 매핑을 활용하려면 대상 프레임워크(PCI-DSS 등)를 프롬프트에 명시하세요.

## 관련 문서

- 루트 README: [../../README.md](../../README.md)
- 플러그인 제작 가이드: [../../docs/plugin-development-guide.md](../../docs/plugin-development-guide.md)
