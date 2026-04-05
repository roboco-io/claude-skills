#!/usr/bin/env bash
# =============================================================================
# TiDD (Ticket Driven Development) PreToolUse Hook
# "No Ticket, No Commit"
#
# 커밋 메시지 또는 브랜치명에 티켓 번호가 있는지 검증합니다.
# Claude Code의 PreToolUse (Bash) 훅으로 동작합니다.
#
# 입력: stdin으로 JSON (tool_input.command)
# 출력: 차단 시 stdout에 안내 메시지, exit 2
# =============================================================================

set -euo pipefail

# --- JSON 파싱 ---
INPUT=$(cat)

COMMAND=""
if command -v jq &>/dev/null; then
  COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null || true)
elif command -v python3 &>/dev/null; then
  COMMAND=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('tool_input', {}).get('command', ''))
except:
    pass
" 2>/dev/null || true)
fi

# JSON 파싱 실패 시 원본 사용
if [ -z "$COMMAND" ]; then
  COMMAND="$INPUT"
fi

# --- git commit 명령만 검사 ---
if ! echo "$COMMAND" | grep -qE '\bgit\s+commit\b'; then
  exit 0
fi

# --- amend는 원본 커밋의 티켓을 유지하므로 통과 ---
if echo "$COMMAND" | grep -qE '\-\-amend'; then
  exit 0
fi

# --- 설정 로드 ---
DEFAULT_PATTERNS='#[0-9]+|[A-Z][A-Z0-9]+-[0-9]+'
DEFAULT_EXEMPT_BRANCHES=""
DEFAULT_EXEMPT_TYPES="merge|revert"

TICKET_PATTERN="$DEFAULT_PATTERNS"
BRANCH_EXTRA_PATTERN=""
EXEMPT_BRANCHES="$DEFAULT_EXEMPT_BRANCHES"
EXEMPT_TYPES="$DEFAULT_EXEMPT_TYPES"

CONFIG_FILE=".tidd.json"
if [ -f "$CONFIG_FILE" ] && command -v python3 &>/dev/null; then
  eval "$(python3 -c "
import json, sys
try:
    with open('$CONFIG_FILE') as f:
        c = json.load(f)

    patterns = c.get('patterns', [])
    if patterns:
        print('TICKET_PATTERN=\"' + '|'.join(patterns) + '\"')

    bp = c.get('branchPatterns', [])
    if bp:
        print('BRANCH_EXTRA_PATTERN=\"' + '|'.join(bp) + '\"')

    eb = c.get('exemptBranches', [])
    if eb:
        # glob을 단순 regex로 변환 (* -> .*)
        converted = [b.replace('*', '.*') for b in eb]
        print('EXEMPT_BRANCHES=\"^(' + '|'.join(converted) + ')$\"')

    et = c.get('exemptTypes', [])
    if et:
        print('EXEMPT_TYPES=\"' + '|'.join(et) + '\"')
except Exception:
    pass
" 2>/dev/null || true)"
fi

# --- 현재 브랜치 확인 ---
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")

# --- exempt 브랜치 검사 ---
if [ -n "$BRANCH" ] && [ -n "$EXEMPT_BRANCHES" ] && echo "$BRANCH" | grep -qE "^($EXEMPT_BRANCHES)$"; then
  exit 0
fi

# --- exempt 커밋 타입 검사 (merge, revert 등) ---
if echo "$COMMAND" | grep -qiE "(Merge|Revert)\s"; then
  exit 0
fi

# --- 검사 1: 커밋 메시지에 티켓 번호 ---
if echo "$COMMAND" | grep -qE "$TICKET_PATTERN"; then
  exit 0
fi

# --- 검사 2: 브랜치명에 티켓 번호 ---
if [ -n "$BRANCH" ]; then
  FULL_PATTERN="$TICKET_PATTERN"
  if [ -n "$BRANCH_EXTRA_PATTERN" ]; then
    FULL_PATTERN="$FULL_PATTERN|$BRANCH_EXTRA_PATTERN"
  fi

  if echo "$BRANCH" | grep -qE "$FULL_PATTERN"; then
    exit 0
  fi
fi

# --- 차단 ---
cat << 'EOF'
[TiDD] No Ticket, No Commit!

커밋 메시지 또는 브랜치명에 티켓 번호가 없습니다.

지원 형식:
  GitHub/GitLab: #123
  Jira/Linear:   PROJ-123

해결 방법:
  1. 커밋 메시지에 티켓 번호를 추가하세요
     예: git commit -m "feat: add login #123"
  2. 또는 티켓 번호가 포함된 브랜치에서 작업하세요
     예: git checkout -b feature/PROJ-123-add-login

프로젝트 루트에 .tidd.json을 생성하여 패턴을 커스터마이즈할 수 있습니다.
EOF
exit 2
