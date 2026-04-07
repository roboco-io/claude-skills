---
name: intent-engineering
description: |
  Intent Document(INTENT.md) 생성 및 관리 스킬. 프로젝트의 의도를 Why/What/Not/Learnings로 문서화하고, 탐구와 학습을 통해 의도를 진화시키는 생명주기를 관리한다.
  반드시 사용해야 하는 경우: "intent document", "INTENT.md", "intent engineering", "프로젝트 의도 정리", "왜 만드는지 정리", "프로젝트 목적 문서화", "What/Why/Not 정리", "프로젝트 방향 잡기", "피벗", "프로젝트 종료 판단" 등을 언급하거나, 새 프로젝트를 시작하면서 방향을 잡고 싶다고 할 때. 기존 INTENT.md를 수정하거나 학습 결과를 기록하고 싶을 때도 이 스킬을 사용한다.
---

# Intent Engineering Skill

프로젝트의 의도를 문서화하고, 탐구와 학습을 통해 진화시키는 스킬. 의도는 한 번 적는 것이 아니라 반복 학습을 통해 수렴하는 것이다. 수렴이 안 되면 종료하는 것도 좋은 결정이다.

사용자가 템플릿을 직접 채우면서 자기 의도를 정리하도록 돕는다. AI가 대화로 유도하지 않는다 — 사용자가 쓰고, AI는 구조만 제공한다.

## 핵심 원칙

- **How를 쓰지 않는다.** 구현 방법은 AI가 결정한다. Intent Document에는 의도만 담는다.
- **템플릿 기반.** 각 단계에서 템플릿을 제공하고 사용자가 채운다. AI가 즉흥적으로 질문하지 않는다.
- **최소한만 남긴다.** 불필요한 섹션, 장식, 메타데이터 없이 핵심만.
- **모르는 것은 모른다고 남긴다.** 확신이 없는 부분에 `(?)` 표시를 권장한다. 의도는 학습으로 명확해진다.

## 의도의 생명주기

의도는 네 가지 상태를 거친다:

```
seed → exploring → clarified → (구현)
  │        │            │
  └────────┴────────────┴──→ killed
```

**seed** — 씨앗. "이런 걸 만들면 좋겠다" 수준. Why만 있고 What/Not은 흐릿하거나 없다.

**exploring** — 탐구 중. 프로토타입, 경쟁사 조사, 사용자 인터뷰 등으로 가설을 검증한다. 매 탐구마다 Learnings에 배운 것을 기록한다. What이 구체화되고 Not이 발견된다.

**clarified** — 명확해짐. Why/What/Not이 모두 확신으로 채워짐. 본격 구현으로 넘어갈 수 있다.

**killed** — 종료. 탐구 결과 의미가 없다고 판단. 또는 이미 있는 솔루션으로 충분하다고 판단. 왜 종료했는지를 Learnings에 기록하면 같은 실수를 반복하지 않는다.

## 실행 흐름

### 기존 INTENT.md가 있는 경우

1. 기존 INTENT.md를 읽는다
2. 현재 status를 확인한다
3. 사용자에게 무엇을 하고 싶은지 물어본다 (AskUserQuestion 사용):
   - **학습 기록** — 새로 배운 것을 Learnings에 추가
   - **섹션 수정** — Why/What/Not 중 수정할 섹션 선택
   - **상태 전이** — 다음 단계로 이동 (예: exploring → clarified, 또는 → killed)
4. 선택에 따라 해당 템플릿을 제시하거나 상태를 전이한다
5. 변경 이유를 커밋 메시지에 남기도록 안내한다

### 새로 시작하는 경우

#### Step 1: 상태 판별

사용자의 프롬프트에서 의도의 명확도를 파악하고 시작 상태를 제시한다. AskUserQuestion 도구를 사용한다.

- **seed** — 아이디어만 있고 구체적인 것은 없다. Why 템플릿(explore)만 채운다.
- **exploring** — 어느 정도 방향은 있지만 검증이 필요하다. Why/What/Not 템플릿을 모두 채운다.
- **clarified** — 만들 것이 확실하다. PR-FAQ 스타일로 Why를 작성하고 What/Not을 채운다.

#### Step 2: Why 템플릿 제공

상태에 따라 적절한 템플릿을 제시한다.

- seed / exploring → `templates/why-explore.md` 사용
- clarified → `templates/why-commit.md` 사용

사용자가 채운 내용을 받으면 다음 단계로 진행한다. 부족하더라도 AI가 보충하지 않는다. 사용자의 표현 그대로 존중한다.

#### Step 3: What 템플릿 제공

`templates/what.md`를 읽어서 사용자에게 제시한다.

seed 상태에서는 "지금은 비워둬도 됩니다. 탐구하면서 채워나가세요"라고 안내한다.
exploring 상태에서는 "확인하고 싶은 것 하나만 써도 충분합니다"라고 안내한다.

#### Step 4: Not 템플릿 제공

`templates/not.md`를 읽어서 사용자에게 제시한다.

"지금 당장 떠오르는 것만 적어도 됩니다. 탐구하면서 추가할 수 있습니다"라고 안내한다.

#### Step 5: INTENT.md 생성

사용자가 채운 섹션을 조합하여 프로젝트 루트에 `INTENT.md`를 생성한다.

파일 구조:

```markdown
# INTENT — [프로젝트명]

> status: seed | exploring | clarified | killed

## Why

[사용자가 채운 내용 그대로]

## What

[사용자가 채운 내용 그대로. seed에서는 비어있을 수 있다]

## Not

[사용자가 채운 내용 그대로. seed에서는 비어있을 수 있다]

## Learnings

[아직 없음 — 탐구를 시작하면 여기에 기록한다]
```

#### Step 6: CLAUDE.md 연동

Not 섹션에서 코딩 규칙에 해당하는 항목(기술 제약, 코드 컨벤션 등)을 추출하여, 프로젝트의 CLAUDE.md에 `## Intent Constraints` 섹션으로 추가하거나 업데이트한다.

CLAUDE.md가 없으면 생성한다. 이미 있으면 해당 섹션만 교체한다.

사용자에게 추가할 내용을 보여주고 확인을 받은 후 적용한다.

### 학습 기록 시

사용자가 탐구 결과를 기록하고 싶을 때 `templates/learning.md` 템플릿을 제시한다. 사용자가 채운 내용을 Learnings 섹션에 날짜와 함께 추가한다.

학습 내용에 따라 Why/What/Not 섹션의 수정이 필요한지 사용자에게 확인한다. 필요하면 해당 섹션의 템플릿을 다시 제시한다.

### 상태 전이 시

상태 전이는 사용자가 결정한다. AI는 전이 조건을 안내만 한다.

- **seed → exploring**: 첫 번째 탐구(프로토타입, 조사, 인터뷰)를 시작했을 때
- **exploring → clarified**: Why/What/Not이 모두 확신으로 채워지고 `(?)` 표시가 없을 때
- **→ killed**: 탐구 결과 의미가 없거나, 이미 있는 솔루션으로 충분할 때

killed로 전이할 때는 종료 사유를 Learnings에 기록한다. 발견한 대안 솔루션이 있다면 함께 기록한다.

## 템플릿 파일 위치

모든 템플릿은 이 스킬의 `templates/` 디렉토리에 있다:

- `templates/why-explore.md` — seed/exploring용 Why 템플릿
- `templates/why-commit.md` — clarified용 Why 템플릿
- `templates/what.md` — What 템플릿
- `templates/not.md` — Not 템플릿
- `templates/learning.md` — 학습 기록 템플릿
