#!/usr/bin/env bash
# llm-wiki qmd-index — qmd 인덱스 빌드/갱신.
# Usage: ./qmd_index.sh [wiki-dir]
set -euo pipefail

WIKI_DIR="${1:-./wiki}"

if [ ! -d "$WIKI_DIR" ]; then
  echo "error: wiki directory not found: $WIKI_DIR" >&2
  exit 1
fi

if ! command -v qmd >/dev/null 2>&1; then
  echo "error: qmd 미설치. 설치 후 재시도:" >&2
  echo "  brew install qmd          # macOS" >&2
  echo "  npm install -g @tobilu/qmd  # 기타" >&2
  exit 1
fi

echo "→ qmd index $WIKI_DIR"
qmd index "$WIKI_DIR"

ABS_WIKI="$(cd "$WIKI_DIR" && pwd)"
CONTEXT_NAME="qmd://$(basename "$ABS_WIKI")"
qmd context add "$CONTEXT_NAME" \
  "LLM Wiki: 프로젝트 컨텍스트 위키 (Karpathy 패턴)" 2>/dev/null || true

echo "✓ qmd-index 완료. 검색: qmd query \"<질문>\""
