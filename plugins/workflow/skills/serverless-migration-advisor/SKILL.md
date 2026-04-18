---
name: serverless-migration-advisor
description: AWS always-on 아키텍처(EC2/ALB/ECS/RDS)를 서버리스+Spot 패턴으로 이행할 때 사용. 워크로드 분류, 트레이드오프 평가, 단계별 이행 계획 생성. 구현 how-to는 sagemaker-spot-training 등 후속 스킬로 위임. 트리거 예 - "서버리스 이행", "EC2에서 Lambda로", "Spot 이행", "serverless migration", "ALB에서 API Gateway", "비용 절감 이행".
---

# Serverless Migration Advisor

스캐폴드 상태 — 본문은 Stage F에서 작성됩니다.

## Phase 1-5
- Phase 1: 워크로드 분류 인터뷰
- Phase 2: IaC 스캔 (선택)
- Phase 3: 제약·리스크 심층 인터뷰
- Phase 4: 타겟 아키텍처 매핑
- Phase 5: 리포트 생성

상세 참조: `references/` 디렉토리의 13개 문서 (Stage C/D/E에서 채워짐).
