---
name: draw-diagram
description: Draw.io (.drawio) XML 형식의 다이어그램 생성. 아키텍처 다이어그램, 시퀀스 다이어그램, 플로우차트, ERD 등을 요청할 때 사용. AWS 아이콘을 포함한 클라우드 아키텍처 다이어그램 지원.
---

# Draw.io Diagram Skill

`.drawio` XML 파일을 직접 생성하여 다이어그램을 만듭니다. draw.io는 XML 기반 포맷이므로 AI가 직접 생성 가능합니다.

## 지원 다이어그램 유형

| 유형 | 설명 |
|------|------|
| Architecture | 시스템/클라우드 아키텍처 다이어그램 |
| Flowchart | 프로세스 흐름도 |
| Sequence | 시퀀스 다이어그램 |
| ERD | Entity-Relationship 다이어그램 |
| Network | 네트워크 토폴로지 |
| C4 Model | Context, Container, Component, Code 다이어그램 |

## .drawio XML 기본 구조

모든 다이어그램은 이 기본 구조를 따릅니다:

```xml
<mxfile host="app.diagrams.net" modified="2024-01-01T00:00:00.000Z" agent="Claude" version="24.0.0" type="device">
  <diagram id="diagram-1" name="Page-1">
    <mxGraphModel dx="1422" dy="762" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1169" pageHeight="827" math="0" shadow="0">
      <root>
        <mxCell id="0" />
        <mxCell id="1" parent="0" />
        <!-- 여기에 도형과 연결선 추가 -->
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>
```

**필수 규칙:**
- `id="0"`과 `id="1"` (parent) mxCell은 항상 포함
- 모든 도형의 `parent="1"`, `vertex="1"`
- 모든 연결선의 `parent="1"`, `edge="1"`, `source`, `target` 지정
- id는 고유해야 함 (숫자 또는 문자열)

## 도형 (Vertex) 작성법

### 기본 사각형
```xml
<mxCell id="2" value="서비스명" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;" vertex="1" parent="1">
  <mxGeometry x="100" y="100" width="120" height="60" as="geometry" />
</mxCell>
```

### 주요 스타일 속성

| 속성 | 값 예시 | 설명 |
|------|---------|------|
| `rounded` | `0`, `1` | 모서리 둥글게 |
| `fillColor` | `#dae8fc` | 배경색 |
| `strokeColor` | `#6c8ebf` | 테두리색 |
| `fontColor` | `#232F3E` | 글자색 |
| `fontSize` | `12` | 글자 크기 |
| `fontStyle` | `0`=일반, `1`=볼드, `2`=이탤릭 | 글자 스타일 |
| `whiteSpace` | `wrap` | 텍스트 줄바꿈 |
| `html` | `1` | HTML 렌더링 |
| `shape` | `mxgraph.aws4.lambda` | 커스텀 도형 |
| `aspect` | `fixed` | 비율 고정 |
| `verticalLabelPosition` | `bottom` | 레이블 위치 |
| `verticalAlign` | `top` | 레이블 세로 정렬 |
| `dashed` | `0`, `1` | 점선 테두리 |

### 기본 도형 종류

```
shape=ellipse          # 원/타원
shape=rhombus          # 마름모 (조건 분기)
shape=parallelogram    # 평행사변형
shape=hexagon          # 육각형
shape=cylinder3        # 실린더 (DB)
shape=document         # 문서
shape=process          # 프로세스
shape=mxgraph.flowchart.annotation_1  # 주석
```

## 연결선 (Edge) 작성법

### 기본 화살표
```xml
<mxCell id="e1" value="" style="edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;" edge="1" source="2" target="3" parent="1">
  <mxGeometry relative="1" as="geometry" />
</mxCell>
```

### 레이블이 있는 화살표
```xml
<mxCell id="e2" value="HTTP Request" style="edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;fontSize=10;" edge="1" source="2" target="3" parent="1">
  <mxGeometry relative="1" as="geometry" />
</mxCell>
```

### 연결선 스타일 변형

| 스타일 | 설명 |
|--------|------|
| `edgeStyle=orthogonalEdgeStyle` | 직각 연결 (기본) |
| `edgeStyle=entityRelationEdgeStyle` | ER 다이어그램용 |
| `curved=1` | 곡선 |
| `dashed=1` | 점선 |
| `endArrow=none` | 화살표 없음 |
| `endArrow=block` | 블록 화살표 |
| `endArrow=open` | 열린 화살표 |
| `endArrow=diamond` | 다이아몬드 (집합) |
| `endArrow=diamondThin` | 얇은 다이아몬드 |
| `startArrow=diamond` | 시작점 다이아몬드 |
| `strokeColor=#FF0000` | 선 색상 |
| `strokeWidth=2` | 선 두께 |

## 그룹/컨테이너 작성법

```xml
<!-- 컨테이너 -->
<mxCell id="group1" value="VPC" style="fillColor=none;strokeColor=#FF9900;verticalAlign=top;fontStyle=1;fontColor=#FF9900;rounded=1;" vertex="1" parent="1">
  <mxGeometry x="50" y="50" width="400" height="300" as="geometry" />
</mxCell>

<!-- 컨테이너 안의 도형 (parent를 그룹 id로 지정) -->
<mxCell id="child1" value="EC2" style="..." vertex="1" parent="group1">
  <mxGeometry x="30" y="40" width="78" height="78" as="geometry" />
</mxCell>
```

**핵심**: 자식 도형의 `parent`를 컨테이너의 `id`로 설정하면 자동으로 그룹화됩니다. 자식의 좌표는 부모 컨테이너 기준 상대 좌표입니다.

## AWS 아키텍처 다이어그램

### AWS 아이콘 사용법

AWS 아이콘은 `shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.[아이콘명]` 형식을 사용합니다.

```xml
<mxCell id="lambda1" value="Lambda"
  style="sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=#F78E04;gradientDirection=north;fillColor=#D05C17;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=12;fontStyle=0;aspect=fixed;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.lambda;"
  vertex="1" parent="1">
  <mxGeometry x="120" y="160" width="78" height="78" as="geometry" />
</mxCell>
```

### AWS 아이콘 크기 규칙
- 서비스 아이콘: `width="78" height="78"` (기본)
- 리소스 아이콘: `width="48" height="48"` (작은 크기)
- 그룹 아이콘: 컨테이너 크기에 맞게 조정

### AWS 카테고리별 색상

| 카테고리 | fillColor | gradientColor |
|----------|-----------|---------------|
| Compute | `#D05C17` | `#F78E04` |
| Database | `#3334B9` | `#4D72F8` |
| Storage | `#3F8624` | `#60A337` |
| Networking | `#8C4FFF` | `#C18FFF` |
| Security | `#DD344C` | `#FF6680` |
| App Integration | `#E7157B` | `#FF4FA2` |
| Management | `#E7157B` | `#FF4FA2` |
| Analytics | `#8C4FFF` | `#C18FFF` |
| AI/ML | `#01A88D` | `#60C6A1` |

### 자주 쓰는 AWS 아이콘 (빠른 참조)

| 서비스 | Shape ID |
|--------|----------|
| EC2 | `mxgraph.aws4.ec2` |
| Lambda | `mxgraph.aws4.lambda` |
| Fargate | `mxgraph.aws4.fargate` |
| ECS | `mxgraph.aws4.ecs` |
| EKS | `mxgraph.aws4.eks` |
| S3 | `mxgraph.aws4.s3` |
| DynamoDB | `mxgraph.aws4.dynamodb` |
| RDS | `mxgraph.aws4.rds` |
| Aurora | `mxgraph.aws4.aurora` |
| ElastiCache | `mxgraph.aws4.elasticache` |
| API Gateway | `mxgraph.aws4.api_gateway` |
| CloudFront | `mxgraph.aws4.cloudfront` |
| Route 53 | `mxgraph.aws4.route_53` |
| VPC | `mxgraph.aws4.vpc` |
| ALB | `mxgraph.aws4.application_load_balancer` |
| NLB | `mxgraph.aws4.network_load_balancer` |
| SQS | `mxgraph.aws4.sqs` |
| SNS | `mxgraph.aws4.sns` |
| EventBridge | `mxgraph.aws4.eventbridge` |
| Step Functions | `mxgraph.aws4.step_functions` |
| CloudWatch | `mxgraph.aws4.cloudwatch` |
| IAM | `mxgraph.aws4.iam` |
| Cognito | `mxgraph.aws4.cognito` |
| WAF | `mxgraph.aws4.waf` |
| Bedrock | `mxgraph.aws4.bedrock` |
| SageMaker | `mxgraph.aws4.sagemaker` |
| CodePipeline | `mxgraph.aws4.codepipeline` |
| CloudFormation | `mxgraph.aws4.cloudformation` |

전체 AWS 아이콘 목록은 [aws-icons.md](references/aws-icons.md) 참조.

### AWS 그룹 스타일

| 그룹 | 스타일 |
|------|--------|
| AWS Cloud | `fillColor=none;strokeColor=#232F3E;dashed=1;verticalAlign=top;fontStyle=0;fontColor=#232F3E;` |
| Region | `fillColor=none;strokeColor=#00A4A6;dashed=1;verticalAlign=top;fontStyle=0;fontColor=#00A4A6;` |
| Availability Zone | `fillColor=none;strokeColor=#7AA116;dashed=1;verticalAlign=top;fontStyle=0;fontColor=#7AA116;` |
| VPC | `fillColor=none;strokeColor=#FF9900;verticalAlign=top;fontStyle=0;fontColor=#FF9900;` |
| Public Subnet | `fillColor=none;strokeColor=#248814;dashed=0;verticalAlign=top;fontStyle=0;fontColor=#248814;` |
| Private Subnet | `fillColor=none;strokeColor=#147EBA;dashed=0;verticalAlign=top;fontStyle=0;fontColor=#147EBA;` |
| Security Group | `fillColor=none;strokeColor=#DD3A0A;dashed=0;verticalAlign=top;fontStyle=0;fontColor=#DD3A0A;` |
| Auto Scaling Group | `fillColor=none;strokeColor=#FF9900;dashed=1;verticalAlign=top;fontStyle=0;fontColor=#FF9900;` |

## 레이아웃 가이드라인

### 배치 규칙
- 좌→우 또는 상→하 방향으로 데이터 흐름 표현
- 동일 계층의 컴포넌트는 같은 Y (수평) 또는 X (수직) 좌표에 배치
- 컴포넌트 간 최소 간격: 40px
- AWS 아이콘 기본 크기 78x78일 때, 아이콘 간 간격 120~160px 권장
- 그룹 컨테이너는 내부 여백 30~50px 확보

### 색상 테마

| 용도 | fillColor | strokeColor |
|------|-----------|-------------|
| 기본 사각형 | `#dae8fc` | `#6c8ebf` |
| 강조 | `#d5e8d4` | `#82b366` |
| 경고/에러 | `#f8cecc` | `#b85450` |
| 외부 시스템 | `#e1d5e7` | `#9673a6` |
| 중립 | `#f5f5f5` | `#666666` |

## SVG/PNG 변환

draw.io 데스크탑 앱 설치 시 CLI를 통해 변환 가능:

```bash
# SVG로 변환
drawio -x -f svg -o output.svg input.drawio

# PNG로 변환 (해상도 지정)
drawio -x -f png -s 2 -o output.png input.drawio

# 특정 페이지만 변환
drawio -x -f svg -p 0 -o page1.svg input.drawio
```

**macOS에서 CLI 설정:**
```bash
# draw.io 앱 설치 후 alias 추가
alias drawio='/Applications/draw.io.app/Contents/MacOS/draw.io'
```

## 생성 프로세스

1. 사용자 요청 분석: 다이어그램 유형, 포함할 컴포넌트 파악
2. AWS 아이콘 필요 시 자주 쓰는 목록에서 확인, 없으면 [aws-icons.md](references/aws-icons.md) 참조
3. `.drawio` XML 생성하여 파일로 저장
4. 사용자에게 VS Code의 draw.io 확장(`hediet.vscode-drawio`)으로 미리보기 안내
5. 필요시 SVG/PNG 변환 명령 안내

## 주의사항

- XML 특수문자 이스케이프: `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`
- `id` 중복 불가 — 고유값 사용
- AWS Shape ID는 대소문자 구분
- 모든 AWS 아이콘은 `mxgraph.aws4.` 접두사 사용
- `aspect=fixed`가 있는 도형은 width와 height를 동일하게 설정
- 그룹 내 자식 좌표는 부모 기준 상대 좌표
