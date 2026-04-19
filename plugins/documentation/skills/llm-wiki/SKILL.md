---
name: llm-wiki
description: Karpathy LLM Wiki 패턴 구현. 프로젝트 문서(스펙/ADR/회의록)를 wiki/raw/에 모으고 LLM이 컴파일하여 wiki/에 교차참조 마크다운 위키를 생성·갱신. qmd 설치 시 하이브리드 검색 자동 활성, 미설치 시 INDEX.md 라우팅으로 graceful degrade. LanceDB 선택적 벡터 인덱스. Obsidian 호환. 하위 명령 - init, ingest, query, lint, sync, export, qmd-index, lancedb-sync.
argument-hint: "[init|ingest|query|lint|sync|export|qmd-index|lancedb-sync] [args]"
---

# llm-wiki

스캐폴드 상태 — 본문은 Stage E에서 작성.
