#!/usr/bin/env bash
# llm-wiki init — 프로젝트 루트에 wiki/ 구조 초기화.
# Usage: ./init.sh [project-root]
set -euo pipefail

PROJECT_ROOT="${1:-$PWD}"
WIKI_DIR="$PROJECT_ROOT/wiki"
RAW_DIR="$WIKI_DIR/raw"
CLAUDE_MD="$PROJECT_ROOT/CLAUDE.md"
SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CLAUDE_BLOCK_TPL="$SKILL_DIR/references/claude-md-block.md"

echo "→ llm-wiki init at: $PROJECT_ROOT"

mkdir -p "$WIKI_DIR" "$RAW_DIR"

if [ ! -f "$WIKI_DIR/index.md" ]; then
  cat > "$WIKI_DIR/index.md" <<EOF
# Wiki Index

> 이 파일은 \`sync_index.py\`로 자동 재빌드됩니다. 수동 편집하지 마세요.

## 페이지 목록

(sync 실행 전)
EOF
  echo "  ✓ wiki/index.md"
fi

if [ ! -f "$WIKI_DIR/log.md" ]; then
  cat > "$WIKI_DIR/log.md" <<EOF
# Wiki Log

Ingest 이력 타임라인. 최신 항목이 위.

EOF
  echo "  ✓ wiki/log.md"
fi

if [ ! -f "$WIKI_DIR/.gitignore" ]; then
  cat > "$WIKI_DIR/.gitignore" <<EOF
# llm-wiki defaults
raw/private/
.lancedb/
EOF
  echo "  ✓ wiki/.gitignore"
fi

if [ -f "$CLAUDE_MD" ]; then
  if ! grep -q "LLM Wiki 활용 규칙" "$CLAUDE_MD" 2>/dev/null; then
    if [ -f "$CLAUDE_BLOCK_TPL" ]; then
      echo "" >> "$CLAUDE_MD"
      cat "$CLAUDE_BLOCK_TPL" >> "$CLAUDE_MD"
      echo "  ✓ CLAUDE.md에 LLM Wiki 블록 추가"
    else
      echo "  ⚠ CLAUDE.md 블록 템플릿 미존재 (Stage D에서 작성): $CLAUDE_BLOCK_TPL"
    fi
  else
    echo "  = CLAUDE.md 이미 LLM Wiki 블록 존재 — 건너뜀"
  fi
else
  if [ -f "$CLAUDE_BLOCK_TPL" ]; then
    {
      echo "# CLAUDE.md"
      echo ""
      echo "This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository."
      echo ""
      cat "$CLAUDE_BLOCK_TPL"
    } > "$CLAUDE_MD"
    echo "  ✓ CLAUDE.md 생성"
  else
    echo "  ⚠ CLAUDE.md 블록 템플릿 미존재 — CLAUDE.md 생성 건너뜀"
  fi
fi

echo ""
echo "→ 환경 감지:"
if command -v qmd >/dev/null 2>&1; then
  echo "  ✓ qmd 감지 — 하이브리드 검색 활성 가능. 'qmd-index' 명령 실행 권장."
else
  echo "  ⚠ qmd 미감지 — INDEX.md 라우팅 모드로 동작. 하이브리드 검색 원하면:"
  echo "    brew install qmd   # macOS"
  echo "    npm install -g @tobilu/qmd   # 기타"
fi

if python3 -c "import lancedb" >/dev/null 2>&1; then
  echo "  ✓ LanceDB 감지 — 벡터 인덱스 활성 가능. 'lancedb-sync' 명령 실행 권장."
else
  echo "  ⚠ LanceDB 미감지 (선택). 원하면: pip install lancedb duckdb sentence-transformers"
fi

echo ""
echo "✓ llm-wiki init 완료."
