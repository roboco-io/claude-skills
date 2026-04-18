# Development 플러그인 (Development)

코드 작성부터 리뷰, 테스트, 시각화까지 개발 전 단계를 지원하는 스킬 모음입니다. 품질 게이트와 설계 일관성을 Claude에게 위임하여 PR 이전에 체크리스트를 자동화할 수 있습니다.

## 특징

- **TDD·품질 중심** — `code-review`와 `test-generator`가 PR 전 품질 게이트를 제공합니다.
- **API 설계 일관성** — `api-design`이 RESTful·GraphQL의 업계 모범 사례를 일관되게 적용합니다.
- **시각적 커뮤니케이션** — `draw-diagram`이 Draw.io(.drawio) 형식의 아키텍처·플로우차트·ERD를 직접 생성합니다(AWS 아이콘 지원).
- **ML 비용 최적화** — `sagemaker-spot-training`이 SageMaker Managed Spot으로 GPU 훈련 비용을 최대 90% 절감하는 실전 가이드(리전 선택·쿼터·인터럽트 처리)를 제공합니다.
- **워크플로 전 단계 커버** — 5개 스킬이 설계 → 구현 → 리뷰 → 테스트 → 문서화의 흐름을 빈틈없이 연결합니다.

## 수록 스킬

| 스킬 | 용도 | 트리거 예시 |
|------|------|-------------|
| [code-review](skills/code-review) | 보안·성능·유지보수성 관점의 구조화된 코드 리뷰 | "이 PR 리뷰해줘", "이 코드 피드백 부탁해" |
| [api-design](skills/api-design) | RESTful API·GraphQL 스키마 설계 및 리소스·엔드포인트 정의 | "사용자 CRUD API 설계해줘", "GraphQL 스키마 잡아줘" |
| [test-generator](skills/test-generator) | 단위·통합·E2E 테스트 스위트 생성 및 커버리지 개선 | "이 함수 단위 테스트 작성해줘", "엣지 케이스 테스트 추가해줘" |
| [draw-diagram](skills/draw-diagram) | Draw.io 아키텍처·시퀀스·플로우차트·ERD 생성 (AWS 아이콘 포함) | "시스템 아키텍처 다이어그램 그려줘", "이 흐름 플로우차트로" |
| [sagemaker-spot-training](skills/sagemaker-spot-training) | AWS SageMaker Managed Spot Training 기반 ML 훈련 비용 최적화 가이드 | "SageMaker Spot 훈련", "GPU 비용 절감", "Spot 용량 디버깅" |

## 사용 예시

### 예시 1 — 새 REST API 엔드포인트 설계
새 기능의 리소스·쿼리 파라미터·응답 스키마를 정의해야 할 때 `api-design`에 요청하면 자원 지향 설계 원칙과 상태 코드 관례를 반영한 엔드포인트를 제안합니다. 이어서 `code-review`가 구현된 핸들러의 입력 검증·에러 처리 누락을 잡아냅니다.

### 예시 2 — PR 열기 전 품질 점검
`code-review`로 변경셋 전체를 훑어 보안·성능 이슈를 선별하고, `test-generator`로 빠진 엣지 케이스 테스트를 생성한 뒤 PR을 올리는 방식으로 리뷰 사이클을 단축합니다.

### 예시 3 — 아키텍처 설명 문서화
설계 회의 결과나 기존 시스템 구조를 공유해야 할 때 `draw-diagram`으로 Draw.io 파일을 생성하면 팀원들이 바로 편집·확장할 수 있는 포맷으로 남습니다.

### 예시 4 — SageMaker Managed Spot으로 ML 훈련 비용 절감
`sagemaker-spot-training`으로 GPU 훈련 작업을 Spot 인스턴스에서 실행하는 베스트 프랙티스(리전 선택, 쿼터 확인, 인터럽트 처리)를 적용하여 on-demand 대비 최대 90% 비용 절감을 달성합니다.

## 설치

```bash
/plugin marketplace add roboco-io/plugins
/plugin install development@roboco-plugins
```

## 관련 문서

- 루트 README: [../../README.md](../../README.md)
- 플러그인 제작 가이드: [../../docs/plugin-development-guide.md](../../docs/plugin-development-guide.md)
