---
name: korean-docs
description: Write technical documentation in Korean following professional standards. Use this skill when users need Korean documentation, README files, API docs, or technical guides written in Korean.
---

# Korean Documentation Skill

전문적인 한국어 기술 문서를 작성합니다.

## 번역 원칙

### 1. 용어 처리 기준

**영문 유지 (번역하지 않음)**
- 프로그래밍 언어: TypeScript, Python, Go, Rust
- 프레임워크/라이브러리: React, Express, Django, Spring
- 도구명: Docker, Kubernetes, Git, npm
- 프로토콜/표준: HTTP, REST, GraphQL, WebSocket
- 고유 개념: hook, middleware, context, state

**한국어로 번역**
- 일반 기술 용어: 배포(deployment), 설정(configuration), 의존성(dependency)
- 동작 설명: 실행하다, 설치하다, 구성하다
- 개념 설명: 컴포넌트, 모듈, 함수, 클래스

### 2. 문체 가이드

**경어체 사용**
```
좋음: "다음 명령어를 실행합니다."
피할 것: "다음 명령어를 실행해라."
```

**간결하고 명확하게**
```
좋음: "환경 변수를 설정합니다."
피할 것: "환경 변수를 설정하는 것이 필요합니다."
```

**능동태 선호**
```
좋음: "시스템이 요청을 처리합니다."
피할 것: "요청이 시스템에 의해 처리됩니다."
```

## 문서 구조

### README.md 템플릿

```markdown
# 프로젝트명

프로젝트에 대한 간단한 설명 (1-2문장)

## 주요 기능

- 기능 1
- 기능 2
- 기능 3

## 시작하기

### 사전 요구사항

- Node.js 18 이상
- npm 또는 yarn

### 설치

\`\`\`bash
npm install
\`\`\`

### 실행

\`\`\`bash
npm start
\`\`\`

## 사용법

기본적인 사용 예제를 포함합니다.

## 설정

환경 변수나 설정 파일에 대해 설명합니다.

## 라이선스

MIT License
```

### API 문서 템플릿

```markdown
## API 레퍼런스

### 엔드포인트 목록

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | /api/users | 사용자 목록 조회 |
| POST | /api/users | 사용자 생성 |

### GET /api/users

사용자 목록을 조회합니다.

**요청 파라미터**

| 이름 | 타입 | 필수 | 설명 |
|------|------|------|------|
| page | number | 아니오 | 페이지 번호 (기본값: 1) |

**응답 예시**

\`\`\`json
{
  "data": [...],
  "total": 100
}
\`\`\`
```

## 품질 기준

### 필수 포함 사항
- 명확한 제목과 설명
- 설치 및 실행 방법
- 사용 예제 (코드 포함)
- 에러 처리 및 문제 해결

### 피해야 할 것
- 불필요한 영문 직역
- 과도한 존칭이나 격식
- 모호한 표현
- 검증되지 않은 예제 코드
