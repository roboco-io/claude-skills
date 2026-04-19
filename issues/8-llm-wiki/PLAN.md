# Issue #8: llm-wiki 구현 계획

> **전제**: `SPEC.md` 승인 완료 (2026-04-19).
> **구현 위치**: `plugins/documentation/skills/llm-wiki/`.
> **총 예상 공수**: ~1.5일(1인). 포팅 0.5일 + 신규 references+scripts 0.5일 + SKILL.md+통합 0.5일.

## 0. 선행 조건

- [x] HANDOFF.md 읽음 (~/Downloads/LLM_WIKI_HANDOFF.md)
- [x] Research report 읽음 (~/Downloads/llm-wiki-qmd-vectordb-complete-report.md)
- [x] SPEC.md 작성 및 승인
- [x] TASKS.md bite-sized 계획 작성
- [x] 포팅 원본 접근 확인 (wjtb-cmc/.claude/skills/llm-wiki/)

---

## 1. 구현 단계

### Stage B — 스킬 스캐폴드 (~0.2일)

- SKILL.md stub (frontmatter만) + 6 reference stubs + 5 script stubs
- `.claude-plugin/marketplace.json` documentation.skills 배열에 등록
- `npm test` green 확인
- **Deliverable**: 스킬 구조 존재, 내용은 이후 단계에서 채움

### Stage C — 스크립트 포팅 + 신규 (~0.5일)

- C1 init.sh 포팅 + `wiki/` 컨벤션 반영 + qmd/LanceDB 감지
- C2 sync_index.py 포팅 + zero-dep frontmatter 파싱
- C3 lint_wiki.py 포팅 + 끊어진 링크·고아·frontmatter 검증
- C4 qmd_index.sh 신규 (qmd CLI 래퍼 + 설치 안내)
- C5 lancedb_sync.py 신규 (LanceDB 벡터 인덱스 + 의존성 graceful)
- 각 스크립트 sanity test로 동작 확인

### Stage D — references 포팅 + 신규 (~0.5일)

- D1 page-templates.md 포팅 + LEP-특수 예시 제거
- D2 ingest-workflow.md 포팅 + 일반화
- D3 claude-md-block.md 포팅 + `wiki/` 경로 반영 + 워크스페이스 CLAUDE.md 규칙 정렬
- D4 qmd-integration.md 신규 (설치·MCP·검색 모드 3종)
- D5 lancedb-integration.md 신규 (Phase 3 옵션, Embedding Atlas 연결)
- D6 karpathy-pattern.md 신규 (원본 패턴 + 본 구현 결정 기록)

### Stage E — SKILL.md 본문 (~0.2일)

- E1 8-command 오케스트레이터 본문 (≤300 lines)
- Phase 1-5 워크플로가 아닌 8개 명령 실행 순서로 구성 (SKILL.md는 sub-command dispatcher)
- Graceful degrade 원칙 명시
- Progressive disclosure로 상세는 references/로

### Stage F — 통합 (~0.1일)

- F1 root README.md Documentation 섹션에 llm-wiki 행 추가
- F2 plugins/documentation/README.md 특징·스킬 테이블·사용 예시 업데이트
- F3 CHANGELOG.md [Unreleased] ### Added 엔트리

### Stage G — 검증 + PR (~0.1일)

- G1 E2E 라운드트립: init → sync → lint (clean + broken link 감지)
- G1 graceful degrade: qmd 없는 환경에서 qmd_index/lancedb_sync 설치 안내 exit 1
- G2 `npm test` 전부 green
- G2 SKILL.md 줄 수 ≤300
- G3 브랜치 push + PR 생성 (#8 closes)

---

## 2. 리스크 및 완화

| 리스크 | 영향 | 완화 |
|-------|------|------|
| wjtb-cmc 스킬에 LEP 특수 로직이 숨어있음 | 일반화 누락 시 다른 프로젝트에서 오동작 | 포팅 시 `grep -i lep`로 전부 제거 후 sanity test |
| qmd CLI 옵션이 2026-04 기준과 달라짐 | qmd_index.sh 동작 실패 | 스크립트 상단에 snapshot 주석, qmd 미설치 graceful |
| Python 표준에 YAML 부재 | sync_index/lint_wiki 파싱 실패 | 수동 frontmatter 파싱 (zero-dep), 복잡 YAML은 미지원 명시 |
| LanceDB v0.23.x 베타 | API 변경 위험 | lancedb-sync.py가 LanceDB 미설치 시 graceful degrade, 버전 변경 시 스크립트 수정 |
| 명령 8개가 많음 | SKILL.md description 토큰 낭비 | 핵심 트리거 키워드만 description에, 나머지는 argument-hint로 |

---

## 3. 의사결정 (구현 중)

- **Python 버전**: 3.8+ (표준 라이브러리만 사용, f-string·pathlib 전제)
- **frontmatter 파싱**: zero-dep 수동 파서 (pyyaml 의존 회피)
- **임베딩 모델 기본**: `all-MiniLM-L6-v2` (CPU에서 빠름) — 한국어 필요 시 `Qwen3-Embedding-0.6B` 권장
- **qmd 컨텍스트 명칭**: `qmd://wiki` (프로젝트 루트 기준 basename 사용)
- **exit code 정책**: graceful degrade는 exit 0 + 경고, 명시 명령 의존성 미설치는 exit 1 + 설치 안내

---

## 4. 산출물 체크리스트

- [ ] `plugins/documentation/skills/llm-wiki/SKILL.md`
- [ ] `references/page-templates.md`
- [ ] `references/ingest-workflow.md`
- [ ] `references/claude-md-block.md`
- [ ] `references/qmd-integration.md`
- [ ] `references/lancedb-integration.md`
- [ ] `references/karpathy-pattern.md`
- [ ] `scripts/init.sh`
- [ ] `scripts/sync_index.py`
- [ ] `scripts/lint_wiki.py`
- [ ] `scripts/qmd_index.sh`
- [ ] `scripts/lancedb_sync.py`
- [ ] `.claude-plugin/marketplace.json` 업데이트
- [ ] root `README.md` 목록 업데이트
- [ ] `plugins/documentation/README.md` 업데이트
- [ ] `CHANGELOG.md` 엔트리
- [ ] `npm test` green
- [ ] E2E sanity 통과

---

## 5. 수락 기준

SPEC §11 성공 기준 + 다음:

- [ ] `npm test` 전부 green (Stage B 이후 유지)
- [ ] SKILL.md 300줄 이하
- [ ] 모든 references/*.md에 `Snapshot date` 표기
- [ ] init → sync → lint 라운드트립 exit 0
- [ ] 깨진 링크·고아 페이지 주입 시 lint exit 1
- [ ] qmd 미설치 환경에서 `query` INDEX.md 라우팅 동작
- [ ] `lancedb-sync` 미설치 시 `pip install` 안내 exit 1

---

*본 계획 생성: 2026-04-19. SPEC 승인 후 TASKS.md 기준으로 구현.*
