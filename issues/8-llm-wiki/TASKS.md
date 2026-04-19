# llm-wiki Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `plugins/documentation/skills/llm-wiki/` — a Karpathy LLM Wiki skill with `init/ingest/query/lint/sync/export/qmd-index/lancedb-sync` commands, graceful qmd fallback, and optional LanceDB vector indexing.

**Architecture:** Port + generalize the existing `wjtb-cmc/.claude/skills/llm-wiki/` skill. Convert `.wiki/` → `wiki/` visible directory to match workspace CLAUDE.md convention. Add qmd/LanceDB integration layers. 6 reference docs + 5 scripts + SKILL.md (≤300 lines).

**Tech Stack:** Markdown (SKILL + references), YAML frontmatter, bash + Python 3.8+ (stdlib + optional `lancedb`/`duckdb`), external CLIs (`qmd`), existing Vitest harness.

---

## File Structure

```
plugins/documentation/skills/llm-wiki/              # CREATE
├── SKILL.md                                        # ≤300 lines, 8-command orchestrator
├── references/                                     # CREATE
│   ├── page-templates.md                           # PORT from wjtb-cmc (223 lines)
│   ├── ingest-workflow.md                          # PORT from wjtb-cmc (121 lines)
│   ├── claude-md-block.md                          # PORT + adapt wiki/ path (wjtb-cmc 33 lines)
│   ├── qmd-integration.md                          # NEW
│   ├── lancedb-integration.md                      # NEW
│   └── karpathy-pattern.md                         # NEW
└── scripts/                                        # CREATE
    ├── init.sh                                     # PORT + generalize (wjtb-cmc 79 lines)
    ├── sync_index.py                               # PORT + generalize (wjtb-cmc 132 lines)
    ├── lint_wiki.py                                # PORT + generalize (wjtb-cmc 138 lines)
    ├── qmd_index.sh                                # NEW
    └── lancedb_sync.py                             # NEW

.claude-plugin/marketplace.json                     # MODIFY — add skill path
plugins/documentation/README.md                     # MODIFY — add row + bullet + example
README.md                                           # MODIFY — root Documentation section
CHANGELOG.md                                        # MODIFY — Unreleased entry

issues/8-llm-wiki/PLAN.md                           # CREATE — stage overview (companion to this file)
```

**Source of truth for port:** `/Users/dohyunjung/Workspace/wjtb/wjtb-cmc/.claude/skills/llm-wiki/`

**Test command:** `npm test` (197+ tests expected green after skill registered)

---

## Stage A — Research & Write PLAN.md

### Task A1: Write PLAN.md stage overview

**Files:**
- Create: `issues/8-llm-wiki/PLAN.md`

- [ ] **Step 1: Write PLAN.md**

Content template (adapt from `issues/3-serverless-migration/PLAN.md` structure):

```markdown
# Issue #8: llm-wiki 구현 계획

> **전제**: `SPEC.md` 승인 후 착수 (완료: 2026-04-19).
> **구현 위치**: `plugins/documentation/skills/llm-wiki/`.
> **총 예상 공수**: ~1.5일(1인). 포팅 0.5일 + 신규 references+scripts 0.5일 + SKILL.md+통합 0.5일.

## 0. 선행 조건
- [x] HANDOFF.md 읽음 (~/Downloads/LLM_WIKI_HANDOFF.md)
- [x] Research report 읽음 (~/Downloads/llm-wiki-qmd-vectordb-complete-report.md)
- [x] SPEC.md 작성
- [ ] SPEC.md 사용자 승인 — Stage B 시작 전 필수
- [x] 포팅 원본 접근 확인 (wjtb-cmc/.claude/skills/llm-wiki/)

## 1. 구현 단계

### Stage B — 스킬 스캐폴드 (~0.2일)
...

### Stage C — 스크립트 포팅 + 신규 (~0.5일)
...

### Stage D — references 포팅 + 신규 (~0.5일)
...

### Stage E — SKILL.md 본문 (~0.2일)
...

### Stage F — 통합 (~0.1일)
...

## 2. 리스크 및 완화
| 리스크 | 영향 | 완화 |
|-------|------|------|
| wjtb-cmc 스킬에 LEP 특수 로직이 숨어있음 | 일반화 누락 시 다른 프로젝트에서 오동작 | 포팅 시 grep으로 "LEP" 전부 제거 후 테스트 |
| qmd CLI 옵션이 2026-04 기준과 달라짐 | qmd_index.sh 동작 실패 | 스크립트 상단에 버전 주석, qmd 미설치 graceful |
| Python 표준 YAML 부재 | sync_index/lint_wiki 파싱 실패 | 수동 frontmatter 파싱 구현 (zero-dep) |

## 3. 수락 기준
- [ ] SPEC §11 기능 체크리스트 전부 통과
- [ ] `npm test` green
- [ ] SKILL.md ≤300 lines
- [ ] Tier별 시나리오 3개 read-through 통과
```

- [ ] **Step 2: Commit**

```bash
git add issues/8-llm-wiki/PLAN.md
git commit -m "docs(issues/8): add PLAN for llm-wiki stage overview (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

---

## Stage B — Scaffold skill directory

### Task B1: Create skill + empty stubs

**Files:**
- Create: `plugins/documentation/skills/llm-wiki/SKILL.md`
- Create: `plugins/documentation/skills/llm-wiki/references/` (6 stub files)
- Create: `plugins/documentation/skills/llm-wiki/scripts/` (5 stub files)

- [ ] **Step 1: Create SKILL.md stub**

Write to `plugins/documentation/skills/llm-wiki/SKILL.md`:

```markdown
---
name: llm-wiki
description: Karpathy LLM Wiki 패턴 구현. 프로젝트 문서(스펙/ADR/회의록)를 wiki/raw/에 모으고 LLM이 컴파일하여 wiki/에 교차참조 마크다운 위키를 생성·갱신. qmd 설치 시 하이브리드 검색 자동 활성, 미설치 시 INDEX.md 라우팅으로 graceful degrade. LanceDB 선택적 벡터 인덱스. Obsidian 호환. 하위 명령 - init, ingest, query, lint, sync, export, qmd-index, lancedb-sync.
argument-hint: [init|ingest|query|lint|sync|export|qmd-index|lancedb-sync] [args]
---

# llm-wiki

스캐폴드 상태 — 본문은 Stage E에서 작성.
```

- [ ] **Step 2: Create 6 reference stubs**

For each filename, create the file with content:

```markdown
> **Snapshot date**: 2026-04-19
> **Description**: {description}

TBD — Stage D에서 작성.
```

Filenames + descriptions:

| File | Description |
|------|-------------|
| `page-templates.md` | 위키 페이지 6개 유형 템플릿 (concept/decision/entity/meeting/policy/comparison) |
| `ingest-workflow.md` | Ingest 5단계 상세 가이드 |
| `claude-md-block.md` | 사용자 프로젝트 CLAUDE.md에 추가할 LLM Wiki 참조 블록 |
| `qmd-integration.md` | qmd 설치·컨텍스트 등록·하이브리드 검색 옵션 |
| `lancedb-integration.md` | LanceDB 벡터 인덱스 + Embedding Atlas 연결 |
| `karpathy-pattern.md` | Karpathy 원본 패턴 요약 및 본 구현 결정 기록 |

- [ ] **Step 3: Create 5 script stubs**

```bash
# init.sh
cat > plugins/documentation/skills/llm-wiki/scripts/init.sh <<'SH'
#!/usr/bin/env bash
# llm-wiki init — Stage C에서 구현.
exit 1
SH
chmod +x plugins/documentation/skills/llm-wiki/scripts/init.sh

# sync_index.py
cat > plugins/documentation/skills/llm-wiki/scripts/sync_index.py <<'PY'
#!/usr/bin/env python3
"""llm-wiki sync_index — Stage C에서 구현."""
raise SystemExit(1)
PY
chmod +x plugins/documentation/skills/llm-wiki/scripts/sync_index.py

# lint_wiki.py
cat > plugins/documentation/skills/llm-wiki/scripts/lint_wiki.py <<'PY'
#!/usr/bin/env python3
"""llm-wiki lint — Stage C에서 구현."""
raise SystemExit(1)
PY
chmod +x plugins/documentation/skills/llm-wiki/scripts/lint_wiki.py

# qmd_index.sh
cat > plugins/documentation/skills/llm-wiki/scripts/qmd_index.sh <<'SH'
#!/usr/bin/env bash
# llm-wiki qmd-index — Stage C에서 구현.
exit 1
SH
chmod +x plugins/documentation/skills/llm-wiki/scripts/qmd_index.sh

# lancedb_sync.py
cat > plugins/documentation/skills/llm-wiki/scripts/lancedb_sync.py <<'PY'
#!/usr/bin/env python3
"""llm-wiki lancedb-sync — Stage C에서 구현."""
raise SystemExit(1)
PY
chmod +x plugins/documentation/skills/llm-wiki/scripts/lancedb_sync.py
```

- [ ] **Step 4: Verify directory shape**

Run:
```bash
ls plugins/documentation/skills/llm-wiki/
ls plugins/documentation/skills/llm-wiki/references/ | wc -l
ls plugins/documentation/skills/llm-wiki/scripts/ | wc -l
```
Expect: SKILL.md + references + scripts dirs; `6` references; `5` scripts.

- [ ] **Step 5: Commit**

```bash
git add plugins/documentation/skills/llm-wiki/
git commit -m "scaffold(llm-wiki): create skill + 6 reference stubs + 5 script stubs (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

### Task B2: Register in marketplace.json

**Files:**
- Modify: `.claude-plugin/marketplace.json`

- [ ] **Step 1: Add skill path to documentation.skills**

Current documentation.skills:
```json
"skills": [
  "./skills/korean-docs/SKILL.md",
  "./skills/qa/SKILL.md",
  "./skills/qa-list/SKILL.md",
  "./skills/qa-merge/SKILL.md"
]
```

Append `"./skills/llm-wiki/SKILL.md"` at end (insertion order convention).

- [ ] **Step 2: Run tests**

```bash
npm test
```
Expected: green. If `skills.test.ts` or `integrity.test.ts` fails, fix the SKILL.md frontmatter or path.

- [ ] **Step 3: Commit**

```bash
git add .claude-plugin/marketplace.json
git commit -m "scaffold(llm-wiki): register in marketplace (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

---

## Stage C — Port + generalize scripts

### Task C1: Port init.sh

**Files:**
- Modify: `plugins/documentation/skills/llm-wiki/scripts/init.sh`
- Source: `/Users/dohyunjung/Workspace/wjtb/wjtb-cmc/.claude/skills/llm-wiki/scripts/init.sh` (79 lines)

- [ ] **Step 1: Read source**

```bash
cat /Users/dohyunjung/Workspace/wjtb/wjtb-cmc/.claude/skills/llm-wiki/scripts/init.sh
```

- [ ] **Step 2: Write adapted script**

Write to `plugins/documentation/skills/llm-wiki/scripts/init.sh`:

```bash
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

# 1. 디렉토리 구조 생성
mkdir -p "$WIKI_DIR" "$RAW_DIR"

# 2. 초기 파일 생성 (존재하면 건너뜀)
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

# 3. CLAUDE.md에 LLM Wiki 블록 추가 (없으면 추가, 있으면 건너뜀)
if [ -f "$CLAUDE_MD" ]; then
  if ! grep -q "LLM Wiki 활용 규칙" "$CLAUDE_MD" 2>/dev/null; then
    echo "" >> "$CLAUDE_MD"
    cat "$CLAUDE_BLOCK_TPL" >> "$CLAUDE_MD"
    echo "  ✓ CLAUDE.md에 LLM Wiki 블록 추가"
  else
    echo "  = CLAUDE.md 이미 LLM Wiki 블록 존재 — 건너뜀"
  fi
else
  cat "$CLAUDE_BLOCK_TPL" > "$CLAUDE_MD"
  echo "  ✓ CLAUDE.md 생성"
fi

# 4. qmd / lancedb 감지
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
  echo "  ⚠ LanceDB 미감지 (선택). 원하면: pip install lancedb duckdb"
fi

echo ""
echo "✓ llm-wiki init 완료."
```

- [ ] **Step 3: Sanity test**

```bash
cd /tmp && rm -rf llm-wiki-test && mkdir llm-wiki-test && cd llm-wiki-test
/Users/dohyunjung/Workspace/roboco-io/tools/plugins/plugins/documentation/skills/llm-wiki/scripts/init.sh
```
Expected: creates `wiki/raw/`, `wiki/index.md`, `wiki/log.md`, `wiki/.gitignore`, `CLAUDE.md`. Prints qmd/LanceDB detection.

Cleanup: `cd && rm -rf /tmp/llm-wiki-test`

- [ ] **Step 4: Commit**

```bash
git add plugins/documentation/skills/llm-wiki/scripts/init.sh
git commit -m "feat(llm-wiki): port init.sh with wiki/ convention and env detection (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

### Task C2: Port sync_index.py

**Files:**
- Modify: `plugins/documentation/skills/llm-wiki/scripts/sync_index.py`
- Source: `/Users/dohyunjung/Workspace/wjtb/wjtb-cmc/.claude/skills/llm-wiki/scripts/sync_index.py` (132 lines)

- [ ] **Step 1: Read source and identify LEP-specific portions**

```bash
cat /Users/dohyunjung/Workspace/wjtb/wjtb-cmc/.claude/skills/llm-wiki/scripts/sync_index.py
grep -n "LEP\|lep" /Users/dohyunjung/Workspace/wjtb/wjtb-cmc/.claude/skills/llm-wiki/scripts/sync_index.py
```

- [ ] **Step 2: Adapt and write**

Port the source with these generalizations:
- Change default wiki path from `.wiki/` to `wiki/`
- Remove LEP/project-specific hardcoded category names
- Preserve: frontmatter parsing logic, page grouping, tag extraction
- CLI flag: `--wiki-dir` (default `./wiki`)
- zero-dep: use stdlib only (no pyyaml)

Minimum viable interface (adapt content from source to match):

```python
#!/usr/bin/env python3
"""Rebuild wiki/index.md by scanning wiki/*.md for frontmatter and links.

Usage:
    ./sync_index.py [--wiki-dir PATH]

Default --wiki-dir is ./wiki relative to CWD.
"""
import argparse
import re
import sys
from pathlib import Path
from collections import defaultdict

FRONTMATTER_RE = re.compile(r'\A---\n(.*?)\n---\n', re.DOTALL)

def parse_frontmatter(text):
    """Simple zero-dep YAML-ish frontmatter parser.

    Supports: key: value, key: [a, b, c] (inline list), key: "quoted value"
    Does not support: nested dicts, block lists, multi-line scalars.
    """
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}
    fm_text = m.group(1)
    result = {}
    for line in fm_text.splitlines():
        if not line.strip() or line.strip().startswith('#'):
            continue
        if ':' not in line:
            continue
        k, v = line.split(':', 1)
        k = k.strip()
        v = v.strip()
        if v.startswith('[') and v.endswith(']'):
            v = [x.strip().strip('"\'') for x in v[1:-1].split(',') if x.strip()]
        elif (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        result[k] = v
    return result

def collect_pages(wiki_dir):
    """Scan wiki_dir for *.md (excluding index.md, log.md, raw/)."""
    pages = []
    for md in wiki_dir.rglob('*.md'):
        if md.name in ('index.md', 'log.md'):
            continue
        if 'raw' in md.relative_to(wiki_dir).parts:
            continue
        text = md.read_text(encoding='utf-8')
        fm = parse_frontmatter(text)
        pages.append({
            'path': md.relative_to(wiki_dir),
            'title': fm.get('title', md.stem),
            'type': fm.get('type', 'page'),
            'tags': fm.get('tags', []) if isinstance(fm.get('tags'), list) else [fm.get('tags')] if fm.get('tags') else [],
            'status': fm.get('status', ''),
            'updated': fm.get('updated', ''),
        })
    return pages

def render_index(pages):
    """Render index.md content grouped by type."""
    lines = [
        '# Wiki Index',
        '',
        '> 이 파일은 `sync_index.py`로 자동 재빌드됩니다. 수동 편집하지 마세요.',
        f'> 총 {len(pages)}개 페이지.',
        '',
    ]
    groups = defaultdict(list)
    for p in pages:
        groups[p['type']].append(p)
    for type_name in sorted(groups.keys()):
        lines.append(f'## {type_name.capitalize()} ({len(groups[type_name])})')
        lines.append('')
        for p in sorted(groups[type_name], key=lambda x: str(x['path'])):
            tags_str = f" — tags: {', '.join(p['tags'])}" if p['tags'] else ''
            status_str = f" [{p['status']}]" if p['status'] else ''
            lines.append(f"- [[{p['path'].stem}|{p['title']}]]{status_str}{tags_str}")
        lines.append('')
    return '\n'.join(lines)

def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--wiki-dir', default='./wiki', help='wiki directory (default ./wiki)')
    args = parser.parse_args()

    wiki_dir = Path(args.wiki_dir).resolve()
    if not wiki_dir.is_dir():
        print(f"error: wiki directory not found: {wiki_dir}", file=sys.stderr)
        return 1

    pages = collect_pages(wiki_dir)
    index_content = render_index(pages)
    index_path = wiki_dir / 'index.md'
    index_path.write_text(index_content, encoding='utf-8')
    print(f"✓ {index_path} 재빌드 완료 ({len(pages)} 페이지)")
    return 0

if __name__ == '__main__':
    sys.exit(main())
```

- [ ] **Step 3: Sanity test**

```bash
cd /tmp && rm -rf llm-wiki-test && mkdir llm-wiki-test && cd llm-wiki-test
/Users/dohyunjung/Workspace/roboco-io/tools/plugins/plugins/documentation/skills/llm-wiki/scripts/init.sh
cat > wiki/alpha.md <<'EOF'
---
title: Alpha
type: concept
tags: [test]
status: draft
updated: 2026-04-19
---
# Alpha
Body
EOF
cat > wiki/beta.md <<'EOF'
---
title: Beta
type: decision
updated: 2026-04-19
---
# Beta
EOF
python3 /Users/dohyunjung/Workspace/roboco-io/tools/plugins/plugins/documentation/skills/llm-wiki/scripts/sync_index.py --wiki-dir ./wiki
cat wiki/index.md
```
Expected: `## Concept (1)` with Alpha, `## Decision (1)` with Beta.

Cleanup: `cd && rm -rf /tmp/llm-wiki-test`

- [ ] **Step 4: Commit**

```bash
git add plugins/documentation/skills/llm-wiki/scripts/sync_index.py
git commit -m "feat(llm-wiki): port sync_index.py with zero-dep frontmatter parsing (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

### Task C3: Port lint_wiki.py

**Files:**
- Modify: `plugins/documentation/skills/llm-wiki/scripts/lint_wiki.py`
- Source: `/Users/dohyunjung/Workspace/wjtb/wjtb-cmc/.claude/skills/llm-wiki/scripts/lint_wiki.py` (138 lines)

- [ ] **Step 1: Read source**

```bash
cat /Users/dohyunjung/Workspace/wjtb/wjtb-cmc/.claude/skills/llm-wiki/scripts/lint_wiki.py
```

- [ ] **Step 2: Adapt**

Port with:
- Default `--wiki-dir ./wiki`
- Check: broken `[[links]]`, orphan pages (not linked from index.md), frontmatter required fields (`title`, `updated`), confidence flag
- Return exit code 0 (green) or 1 (issues found)

Minimum viable structure:

```python
#!/usr/bin/env python3
"""Lint wiki/*.md for broken links, orphans, and missing frontmatter.

Usage:
    ./lint_wiki.py [--wiki-dir PATH]

Exit code 0 if clean, 1 if issues.
"""
import argparse
import re
import sys
from pathlib import Path

WIKILINK_RE = re.compile(r'\[\[([^\]|]+)(?:\|[^\]]+)?\]\]')
FRONTMATTER_RE = re.compile(r'\A---\n(.*?)\n---\n', re.DOTALL)
REQUIRED_FM = ['title', 'updated']

def parse_frontmatter(text):
    """Same parser as sync_index.py — kept inline for zero-dep."""
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}
    result = {}
    for line in m.group(1).splitlines():
        if not line.strip() or line.strip().startswith('#') or ':' not in line:
            continue
        k, v = line.split(':', 1)
        result[k.strip()] = v.strip()
    return result

def lint(wiki_dir):
    md_files = [p for p in wiki_dir.rglob('*.md') if 'raw' not in p.relative_to(wiki_dir).parts]
    page_stems = {p.stem for p in md_files if p.name not in ('index.md', 'log.md')}

    issues = []
    referenced = set()

    for md in md_files:
        if md.name in ('index.md', 'log.md'):
            text = md.read_text(encoding='utf-8')
            for link in WIKILINK_RE.findall(text):
                referenced.add(link.strip())
            continue

        text = md.read_text(encoding='utf-8')
        fm = parse_frontmatter(text)

        for field in REQUIRED_FM:
            if field not in fm or not fm[field]:
                issues.append(f"{md.relative_to(wiki_dir)}: frontmatter `{field}` missing")

        confidence = fm.get('confidence', '').lower()
        if confidence in ('low', 'tentative'):
            issues.append(f"{md.relative_to(wiki_dir)}: low-confidence page flagged")

        for link in WIKILINK_RE.findall(text):
            target = link.strip()
            referenced.add(target)
            if target not in page_stems:
                issues.append(f"{md.relative_to(wiki_dir)}: broken link [[{target}]]")

    orphans = page_stems - referenced
    for orphan in sorted(orphans):
        issues.append(f"wiki/{orphan}.md: orphan (not referenced from any page)")

    return issues

def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--wiki-dir', default='./wiki')
    args = parser.parse_args()

    wiki_dir = Path(args.wiki_dir).resolve()
    if not wiki_dir.is_dir():
        print(f"error: wiki directory not found: {wiki_dir}", file=sys.stderr)
        return 1

    issues = lint(wiki_dir)
    if not issues:
        print(f"✓ clean ({sum(1 for _ in wiki_dir.rglob('*.md'))} files)")
        return 0

    print(f"⚠ {len(issues)} issue(s):", file=sys.stderr)
    for issue in issues:
        print(f"  - {issue}", file=sys.stderr)
    return 1

if __name__ == '__main__':
    sys.exit(main())
```

- [ ] **Step 3: Sanity test with orphan**

```bash
cd /tmp && rm -rf llm-wiki-test && mkdir llm-wiki-test && cd llm-wiki-test
mkdir -p wiki/raw
cat > wiki/index.md <<'EOF'
# Wiki Index
- [[alpha]]
EOF
cat > wiki/alpha.md <<'EOF'
---
title: Alpha
updated: 2026-04-19
---
# Alpha
See [[beta]] for details.
EOF
cat > wiki/orphan.md <<'EOF'
---
title: Orphan
updated: 2026-04-19
---
# Orphan
EOF
python3 /Users/dohyunjung/Workspace/roboco-io/tools/plugins/plugins/documentation/skills/llm-wiki/scripts/lint_wiki.py --wiki-dir ./wiki
```
Expected: exit 1 with issues listing broken link `[[beta]]` and orphan `orphan.md`.

Cleanup: `cd && rm -rf /tmp/llm-wiki-test`

- [ ] **Step 4: Commit**

```bash
git add plugins/documentation/skills/llm-wiki/scripts/lint_wiki.py
git commit -m "feat(llm-wiki): port lint_wiki.py with link/orphan/frontmatter checks (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

### Task C4: New qmd_index.sh

**Files:**
- Modify: `plugins/documentation/skills/llm-wiki/scripts/qmd_index.sh`

- [ ] **Step 1: Write script**

```bash
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

# 컨텍스트 등록 (이미 있으면 qmd 쪽에서 idempotent)
qmd context add "qmd://$(basename "$(cd "$WIKI_DIR" && pwd)")" \
  "LLM Wiki: 프로젝트 컨텍스트 위키 (Karpathy 패턴)" || true

echo "✓ qmd-index 완료. 검색: qmd query \"<질문>\""
```

- [ ] **Step 2: Sanity test (skip if qmd not installed)**

```bash
if command -v qmd >/dev/null 2>&1; then
  cd /tmp && rm -rf llm-wiki-test && mkdir llm-wiki-test && cd llm-wiki-test
  /Users/dohyunjung/Workspace/roboco-io/tools/plugins/plugins/documentation/skills/llm-wiki/scripts/init.sh
  echo "# Test" > wiki/test.md
  /Users/dohyunjung/Workspace/roboco-io/tools/plugins/plugins/documentation/skills/llm-wiki/scripts/qmd_index.sh
  cd && rm -rf /tmp/llm-wiki-test
else
  echo "qmd not installed — skip sanity test, will validate via graceful degrade instead"
fi
```

- [ ] **Step 3: Commit**

```bash
git add plugins/documentation/skills/llm-wiki/scripts/qmd_index.sh
git commit -m "feat(llm-wiki): add qmd_index.sh wrapper with install guidance (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

### Task C5: New lancedb_sync.py

**Files:**
- Modify: `plugins/documentation/skills/llm-wiki/scripts/lancedb_sync.py`

- [ ] **Step 1: Write script**

```python
#!/usr/bin/env python3
"""Sync wiki/*.md into a LanceDB vector index at wiki/.lancedb/.

Requires: pip install lancedb duckdb sentence-transformers

Usage:
    ./lancedb_sync.py [--wiki-dir PATH] [--model MODEL] [--table TABLE]

Graceful failure: exits 1 with pip install guidance if deps missing.
"""
import argparse
import re
import sys
from pathlib import Path

FRONTMATTER_RE = re.compile(r'\A---\n(.*?)\n---\n', re.DOTALL)

def parse_frontmatter(text):
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}
    result = {}
    for line in m.group(1).splitlines():
        if not line.strip() or line.strip().startswith('#') or ':' not in line:
            continue
        k, v = line.split(':', 1)
        result[k.strip()] = v.strip()
    return result

def strip_frontmatter(text):
    m = FRONTMATTER_RE.match(text)
    return text[m.end():] if m else text

def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--wiki-dir', default='./wiki')
    parser.add_argument('--model', default='all-MiniLM-L6-v2',
                        help='sentence-transformers model name')
    parser.add_argument('--table', default='wiki_pages')
    args = parser.parse_args()

    try:
        import lancedb
        from sentence_transformers import SentenceTransformer
    except ImportError as e:
        print(f"error: 필수 의존성 누락 ({e.name}). 설치:", file=sys.stderr)
        print("  pip install lancedb duckdb sentence-transformers", file=sys.stderr)
        return 1

    wiki_dir = Path(args.wiki_dir).resolve()
    if not wiki_dir.is_dir():
        print(f"error: wiki directory not found: {wiki_dir}", file=sys.stderr)
        return 1

    db_dir = wiki_dir / '.lancedb'
    db_dir.mkdir(exist_ok=True)

    print(f"→ 임베딩 모델 로드: {args.model}")
    model = SentenceTransformer(args.model)

    records = []
    for md in wiki_dir.rglob('*.md'):
        if md.name in ('index.md', 'log.md'):
            continue
        if 'raw' in md.relative_to(wiki_dir).parts:
            continue
        text = md.read_text(encoding='utf-8')
        fm = parse_frontmatter(text)
        body = strip_frontmatter(text)
        if not body.strip():
            continue
        vec = model.encode(body).tolist()
        records.append({
            'path': str(md.relative_to(wiki_dir)),
            'title': fm.get('title', md.stem),
            'type': fm.get('type', 'page'),
            'vector': vec,
            'text': body[:10000],  # store preview only
        })

    if not records:
        print("⚠ 인덱싱할 페이지가 없음.")
        return 0

    print(f"→ LanceDB 테이블 '{args.table}' 갱신 ({len(records)} 페이지)")
    db = lancedb.connect(str(db_dir))
    if args.table in db.table_names():
        db.drop_table(args.table)
    db.create_table(args.table, data=records)

    print(f"✓ lancedb-sync 완료. Embedding Atlas: atlas open {db_dir}")
    return 0

if __name__ == '__main__':
    sys.exit(main())
```

- [ ] **Step 2: Sanity test (dry-run without deps)**

```bash
python3 /Users/dohyunjung/Workspace/roboco-io/tools/plugins/plugins/documentation/skills/llm-wiki/scripts/lancedb_sync.py --wiki-dir /tmp/nonexistent
```
Expected: exit 1 with `pip install lancedb...` message (if deps missing) OR wiki not found error.

- [ ] **Step 3: Commit**

```bash
git add plugins/documentation/skills/llm-wiki/scripts/lancedb_sync.py
git commit -m "feat(llm-wiki): add lancedb_sync.py with graceful dep fallback (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

---

## Stage D — Author references

### Task D1: Port page-templates.md

**Files:**
- Modify: `plugins/documentation/skills/llm-wiki/references/page-templates.md`
- Source: `wjtb-cmc/.claude/skills/llm-wiki/references/page-templates.md` (223 lines)

- [ ] **Step 1: Read source and port**

Read the source file fully. Adapt:
- Remove LEP-specific examples (search for "LEP", "lep", project-specific entity names)
- Use generic domain examples (e.g., "rate limiter", "user authentication", "payment processor")
- Preserve the 6 template types: concept / decision / entity / meeting / policy / comparison
- Preserve frontmatter schema

Write to target path.

- [ ] **Step 2: Commit**

```bash
git add plugins/documentation/skills/llm-wiki/references/page-templates.md
git commit -m "docs(llm-wiki): port page-templates with generic domain examples (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

### Task D2: Port ingest-workflow.md

**Files:**
- Modify: `plugins/documentation/skills/llm-wiki/references/ingest-workflow.md`
- Source: `wjtb-cmc/.claude/skills/llm-wiki/references/ingest-workflow.md` (121 lines)

- [ ] **Step 1: Port**

Read source and port. Same generalization principle — remove LEP-specific examples, keep 5-step workflow intact.

- [ ] **Step 2: Commit**

```bash
git add plugins/documentation/skills/llm-wiki/references/ingest-workflow.md
git commit -m "docs(llm-wiki): port ingest-workflow 5-step guide (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

### Task D3: Port + adapt claude-md-block.md

**Files:**
- Modify: `plugins/documentation/skills/llm-wiki/references/claude-md-block.md`
- Source: `wjtb-cmc/.claude/skills/llm-wiki/references/claude-md-block.md` (33 lines)

- [ ] **Step 1: Adapt**

Port with critical change: `.wiki/` → `wiki/` paths throughout. Content describes what Claude Code should do with wiki/ when present. Ensure alignment with workspace CLAUDE.md "LLM Wiki 활용 규칙":

```markdown
## LLM Wiki 활용 규칙

이 프로젝트는 `wiki/` 디렉토리에 [[wiki-link]] 교차참조 위키를 유지한다. Karpathy LLM Wiki 패턴을 따른다.

### 작업 시 우선순위

1. **위키 우선 참조**: 질문에 답하거나 작업을 시작할 때, `wiki/index.md`에서 관련 페이지를 먼저 찾아 읽는다. `[[wiki-link]]`를 따라 2-hop까지 확장하여 맥락을 파악한다.
2. **출처 인용**: 답변 작성 시 위키 페이지를 `[[페이지 제목]]` 형태로 인용한다.
3. **위키에 없으면 명시**: 위키에 답이 없으면 "위키에 없음"이라 표기하고 `raw/` 또는 외부 원본을 읽어 보강한다. 새 내용이면 `llm-wiki ingest`로 위키를 성장시킨다.
4. **검색보다 컴파일**: 매번 원본을 다시 읽지 말고, 이미 컴파일된 위키 지식을 적극 재활용한다.

### 위키 구조

- `wiki/index.md` — 자동 재빌드되는 라우팅 레이어 (수동 편집 금지)
- `wiki/{page}.md` — 컴파일된 지식 페이지 ([[wiki-link]] 교차참조)
- `wiki/raw/` — 원본 소스 드롭존 (불변)
- `wiki/log.md` — ingest 이력
- `wiki/.lancedb/` — 선택적 벡터 인덱스 (lancedb-sync 실행 시)

### 스킬 명령

사용자가 `llm-wiki <command>`를 호출하면 해당 단계 실행:
- `init` — 구조 초기화
- `ingest <source>` — 새 소스를 컴파일해 위키 갱신
- `query <질문>` — 하이브리드 검색(qmd) 또는 INDEX.md 라우팅
- `lint` — 끊어진 링크·고아 페이지 탐지
- `sync` — index.md 재빌드
- `export <template>` — 온보딩·ADR 요약 등 출력
- `qmd-index` — qmd 인덱스 빌드 (선택)
- `lancedb-sync` — LanceDB 벡터 인덱스 동기화 (선택)
```

- [ ] **Step 2: Commit**

```bash
git add plugins/documentation/skills/llm-wiki/references/claude-md-block.md
git commit -m "docs(llm-wiki): port claude-md-block adapted to wiki/ convention (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

### Task D4: New qmd-integration.md

**Files:**
- Modify: `plugins/documentation/skills/llm-wiki/references/qmd-integration.md`

- [ ] **Step 1: Write**

Base content on `~/Downloads/llm-wiki-qmd-vectordb-complete-report.md` §2:

```markdown
> **Snapshot date**: 2026-04-19
> **Description**: qmd 설치·컨텍스트 등록·하이브리드 검색 옵션

# qmd Integration

Karpathy가 LLM Wiki 글에서 검색 백엔드로 추천한 로컬 온디바이스 하이브리드 검색 엔진. BM25 + 벡터 + LLM 재순위를 결합, node-llama-cpp로 완전히 로컬에서 실행. MIT 라이선스.

## 설치

### macOS

```bash
brew install qmd
```

### 기타 (Linux, Windows WSL)

```bash
npm install -g @tobilu/qmd
```

## Claude Code MCP 연동 (권장)

```bash
claude marketplace add tobi/qmd
```

6개 도구 노출: `query`, `search`, `vsearch`, `get`, `multi-get`, `status`.

## 위키 인덱싱

`llm-wiki qmd-index` 명령이 `qmd index wiki/`를 실행. 또는 수동:

```bash
qmd index wiki/
qmd context add qmd://wiki "LLM Wiki: 프로젝트 컨텍스트 위키"
```

## 검색 모드

| 모드 | CLI | 설명 | 속도 |
|------|-----|------|------|
| search | `qmd search "rate limit"` | BM25 키워드 매칭 | ~132ms |
| vsearch | `qmd vsearch "throttling patterns"` | 벡터 시맨틱 | ~2.9초 |
| query | `qmd query "API 제한 패턴"` | 하이브리드 (FTS + vec + LLM 재순위) | ~17-20초 |

LLM Wiki의 `query` 명령은 내부적으로 `qmd query`를 호출 (qmd 감지 시).

## 다국어 지원

한국어/일본어는 기본 모델로도 동작하나, 품질 향상을 원하면:

```bash
export QMD_EMBED_MODEL=Qwen3-Embedding-0.6B
qmd index wiki/  # 재인덱싱
```

## 컨텍스트 트리

qmd의 킬러 피처. 컬렉션별 설명을 추가하여 검색이 문서 위치를 이해하도록:

```bash
qmd context add qmd://wiki "프로젝트 컨텍스트 위키"
qmd context add qmd://wiki/decisions "아키텍처 결정 기록 (ADR)"
qmd context add qmd://wiki/meetings "회의록 요약"
```

## 스마트 청킹

qmd는 마크다운 헤딩·코드 블록·빈 줄에서 자동 분할, 타겟 ~900 토큰 + 15% 오버랩. 코드 블록은 중간 분할 금지. 별도 설정 불필요.

## Reference links

- qmd: https://github.com/tobi/qmd
- lazyqmd (TUI): https://github.com/alexanderzeitler/lazyqmd
- Karpathy LLM Wiki: https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f
```

- [ ] **Step 2: Commit**

```bash
git add plugins/documentation/skills/llm-wiki/references/qmd-integration.md
git commit -m "docs(llm-wiki): add qmd-integration with install + MCP + search modes (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

### Task D5: New lancedb-integration.md

**Files:**
- Modify: `plugins/documentation/skills/llm-wiki/references/lancedb-integration.md`

- [ ] **Step 1: Write**

Base on report §4, §5:

```markdown
> **Snapshot date**: 2026-04-19
> **Description**: LanceDB 벡터 인덱스 + Embedding Atlas 연결

# LanceDB Integration (Phase 3 optional)

> **When to use**: 위키 규모 500페이지 초과, 멀티 에이전트 지식 슬라이싱, Embedding Atlas 시각화 필요 시. 500페이지 미만은 qmd만으로 충분.

## 설치

```bash
pip install lancedb duckdb sentence-transformers
```

임베딩 모델은 `all-MiniLM-L6-v2` (기본, CPU 빠름) 또는 `Qwen3-Embedding-0.6B` (프로덕션 품질, 다국어).

## 인덱스 생성

```bash
./scripts/lancedb_sync.py --wiki-dir ./wiki --model all-MiniLM-L6-v2
```

결과: `wiki/.lancedb/` 디렉토리에 `.lance` 파일 생성. Git에서는 `.gitignore`로 제외(기본).

## Embedding Atlas 연결

```bash
pip install embedding-atlas
atlas open wiki/.lancedb/
```

브라우저에서 WebGPU 렌더링으로 수백만 포인트 가시화. 멀티 코디네이트 뷰 교차 필터링. MCP 지원으로 Claude Code 직접 연동.

## DuckDB SQL 분석

LanceDB는 Lance extension for DuckDB를 통해 DuckDB와 네이티브 통합:

```sql
-- 지난 7일 미업데이트 페이지
SELECT path, title, updated
FROM lance_scan('wiki/.lancedb/wiki_pages.lance')
WHERE updated < CURRENT_DATE - INTERVAL '7 days'
ORDER BY updated ASC;

-- 카테고리별 페이지 수
SELECT type, COUNT(*) as n
FROM lance_scan('wiki/.lancedb/wiki_pages.lance')
GROUP BY type
ORDER BY n DESC;
```

## 트레이드오프 (report §6.2 요약)

- **장점**: 시맨틱 디스커버리, 멀티 에이전트 슬라이싱, 시각화, SQL 분석, 버전 관리 내장
- **단점**: 복잡도 비용, 듀얼 소스 오브 트루스(md ↔ vec), 임베딩 모델 lock-in, LanceDB 베타(v0.23.x)
- **qmd와 중복**: qmd도 이미 BM25+vec+재순위를 제공. LanceDB는 시각화·SQL·멀티슬라이싱이 필요할 때만 추가.

## 단계별 채택

- **Phase 1** (소스 <100): 벡터 DB 없이 Karpathy 원본 설계
- **Phase 2** (100-500): qmd만으로 하이브리드 검색
- **Phase 3** (500+): LanceDB + DuckDB + Embedding Atlas

## Reference links

- LanceDB: https://lancedb.com
- Lance DuckDB extension: https://github.com/lancedb/lance-duckdb
- Apple Embedding Atlas: https://github.com/apple/embedding-atlas
- Anthropic Contextual Retrieval: https://anthropic.com/news/contextual-retrieval
```

- [ ] **Step 2: Commit**

```bash
git add plugins/documentation/skills/llm-wiki/references/lancedb-integration.md
git commit -m "docs(llm-wiki): add lancedb-integration Phase 3 optional guide (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

### Task D6: New karpathy-pattern.md

**Files:**
- Modify: `plugins/documentation/skills/llm-wiki/references/karpathy-pattern.md`

- [ ] **Step 1: Write**

```markdown
> **Snapshot date**: 2026-04-19
> **Source**: https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f
> **Description**: Karpathy 원본 패턴 요약 및 본 구현 결정 기록

# Karpathy LLM Wiki 패턴

## 핵심 아이디어

> RAG는 무상태. Wiki는 복리로 축적된다.

대부분의 LLM 작업은 RAG로 매번 처음부터 지식을 재발견한다. LLM Wiki는 달리, 지속적으로 상호 연결된 지식 베이스를 **증분 구축**한다. 교차 참조가 이미 존재하고, 모순이 이미 플래그되며, 합성 결과가 이전에 수집된 모든 것을 반영한다.

## 3계층 아키텍처

- `raw/` — 불변 입력 문서 (LLM이 읽기만, 수정 금지)
- `wiki/*.md` — LLM이 생성·유지하는 마크다운 (요약, 엔티티 페이지, 개념 비교, 마스터 인덱스)
- `CLAUDE.md` — 스키마·컨벤션 (위키 구조 정의, 워크플로 지시)

## 3가지 핵심 연산

| 연산 | 설명 |
|------|------|
| Ingest | 소스를 넣으면 LLM이 10~15개 위키 페이지를 업데이트 |
| Query | LLM이 인덱스를 검색하고 답변을 합성 |
| Lint | 주기적 건강 점검 — 모순, 부실 주장, 고아 페이지 탐지 |

## 본 구현의 확장 결정

### 1. `wiki/` 노출형 선택

Karpathy 원본은 별도 규정 없음. 본 구현은 워크스페이스 CLAUDE.md의 "LLM Wiki 활용 규칙"이 `wiki/index.md` 존재를 시그널로 쓰도록 규정하므로, 노출형 `wiki/`를 채택. Obsidian에서 vault로 직접 열 수 있는 이점.

### 2. 명령 8개로 확장

Karpathy 원본 3개(Ingest/Query/Lint) + 본 구현 추가 5개:
- `init` — 구조 자동 생성 (Karpathy는 수동 설명만)
- `sync` — `index.md` 결정론적 재빌드 (LLM 오류 방지)
- `export` — 온보딩/ADR/릴리스 노트 템플릿 출력
- `qmd-index` — 하이브리드 검색 백엔드 설정
- `lancedb-sync` — Phase 3 벡터 인덱스

### 3. qmd 통합 (Karpathy 권장)

Karpathy가 LLM Wiki 글에서 qmd를 명시적으로 추천. 본 구현은 qmd 설치 감지 시 자동으로 하이브리드 검색으로 승격, 미설치 시 INDEX.md 라우팅으로 graceful degrade.

### 4. LanceDB는 선택적

Karpathy는 벡터 DB를 명시적으로 배제했다. 이유: 잘 큐레이션된 INDEX.md + LLM 컨텍스트 윈도우가 개인 규모 위키에는 충분. 본 구현도 이 원칙을 존중하여 500페이지 초과 또는 멀티 에이전트 시나리오에서만 권장.

## 규모별 전략

| 규모 | 전략 |
|------|------|
| <100 페이지 | Karpathy 원본 (INDEX.md + LLM 컨텍스트 윈도우) |
| 100~500 페이지 | qmd 하이브리드 검색 활용 |
| 500+ 페이지 | LanceDB + DuckDB + Embedding Atlas 추가 |

## Obsidian 호환

모든 `[[wiki-link]]`는 Obsidian 표준. 사용자는 Obsidian에서 `wiki/` vault를 열어:
- 그래프 뷰로 교차 참조 시각화
- 네이티브 링크 follow
- 마크다운 프리뷰

## 참고

- Karpathy 원문: https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f
- Karpathy 트윗: https://x.com/karpathy/status/2039805659525644595
- Claude Code LLM Wiki 구현 사례: github.com/tinworks-ai/claude-obsidian, github.com/llm-wiki/kb-wiki
```

- [ ] **Step 2: Commit**

```bash
git add plugins/documentation/skills/llm-wiki/references/karpathy-pattern.md
git commit -m "docs(llm-wiki): add karpathy-pattern origin and design decisions (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

---

## Stage E — SKILL.md body

### Task E1: Write full SKILL.md

**Files:**
- Modify: `plugins/documentation/skills/llm-wiki/SKILL.md`

- [ ] **Step 1: Write body (preserve frontmatter from Stage B)**

Write to the SKILL.md file, preserving the existing frontmatter. Body structure:

```markdown
---
name: llm-wiki
description: Karpathy LLM Wiki 패턴 구현. 프로젝트 문서(스펙/ADR/회의록)를 wiki/raw/에 모으고 LLM이 컴파일하여 wiki/에 교차참조 마크다운 위키를 생성·갱신. qmd 설치 시 하이브리드 검색 자동 활성, 미설치 시 INDEX.md 라우팅으로 graceful degrade. LanceDB 선택적 벡터 인덱스. Obsidian 호환. 하위 명령 - init, ingest, query, lint, sync, export, qmd-index, lancedb-sync.
argument-hint: [init|ingest|query|lint|sync|export|qmd-index|lancedb-sync] [args]
---

# llm-wiki — 프로젝트 컨텍스트 위키

> 참고: [Karpathy LLM Wiki](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f).
> **검색이 아닌 컴파일**이 핵심 — 한 번 이해한 것은 계속 다듬어 재활용한다.

## 언제 사용하나

트리거: "wiki 초기화", "문서 wiki로 정리", "프로젝트 컨텍스트 위키", "llm wiki", "knowledge base 구축", "wiki ingest", "wiki query", "서드파티 소스 컴파일".

이 스킬은 워크스페이스 CLAUDE.md의 **"LLM Wiki 활용 규칙"을 실제 실행 가능하게** 한다.

## 디렉토리 구조

프로젝트 루트에 `init` 명령으로 생성되는 구조:

```text
wiki/
├── index.md              # 자동 재빌드 (수동 편집 금지)
├── log.md                # ingest 이력
├── raw/                  # 원본 소스 드롭존 (불변)
│   └── YYYY-MM-DD_{source}.md
├── {page}.md             # 컴파일된 위키 페이지 ([[wiki-link]] 교차참조)
├── .gitignore            # raw/private/, .lancedb/ 기본 제외
└── .lancedb/             # 선택적 벡터 인덱스 (lancedb-sync 시)
```

CLAUDE.md에는 "LLM Wiki 활용 규칙" 블록이 init 시 자동 추가된다.

## 페이지 프론트매터 규약

```yaml
---
title: "Rate Limiter Design"
type: decision          # concept | decision | entity | meeting | policy | comparison
tags: [api, reliability]
status: active          # draft | active | stale | archived
confidence: high        # high | medium | low | tentative
created: 2026-04-19
updated: 2026-04-19
sources: [raw/2026-04-18_arch-review.md]
---
```

상세는 [page-templates.md](references/page-templates.md) 참조.

## 8개 명령 실행 순서

### `init` — 구조 초기화

**실행**: `scripts/init.sh`

- `wiki/` 디렉토리 구조 생성
- `wiki/index.md`, `log.md`, `.gitignore` 초기 파일
- 프로젝트 루트 `CLAUDE.md`에 LLM Wiki 블록 추가 (`references/claude-md-block.md`)
- qmd / LanceDB 환경 감지 및 안내

### `ingest <source>` — 소스 컴파일

상세 워크플로: [ingest-workflow.md](references/ingest-workflow.md)

5단계 요약:
1. 소스 읽기 (사용자가 `raw/`에 드롭 또는 인자로 경로 제공)
2. 엔티티·개념 추출
3. 기존 wiki 페이지와 교차 참조 검토
4. 페이지 생성/갱신 (10-15 페이지)
5. `log.md`에 기록

### `query <질문>` — 위키 검색

**qmd 감지 시**:
1. `qmd query "<질문>"` 호출
2. 하이브리드 검색 결과 top-10 수령
3. LLM이 컨텍스트 트리 + 매칭 페이지로 답변 합성
4. 답변에 `[[wiki-link]]`로 출처 인용

**qmd 미감지 시 (graceful degrade)**:
1. `wiki/index.md` 읽어 관련 페이지 후보 3-5개 식별
2. 후보 페이지 본문 로드 + `[[link]]` 2-hop 확장
3. LLM이 로드된 컨텍스트로 답변
4. "qmd 미설치 — 하이브리드 검색 원하면 `brew install qmd`" 안내 첨부

### `lint` — 건강 점검

**실행**: `scripts/lint_wiki.py`

검사:
- 끊어진 `[[wiki-link]]`
- 고아 페이지 (어디에서도 참조되지 않음)
- frontmatter 필수 필드 누락 (`title`, `updated`)
- `confidence: low` 또는 `tentative` 페이지 플래그

### `sync` — index.md 재빌드

**실행**: `scripts/sync_index.py`

`wiki/*.md` 스캔 → frontmatter `type` 별로 그룹화 → `index.md` 재생성. 수동 편집은 덮어씌워지므로 index에는 내용을 쓰지 말 것.

### `export <template>` — 템플릿 출력

LLM이 wiki 페이지를 템플릿으로 합성. 지원 템플릿:
- `onboarding` — 신규 팀원 온보딩 가이드
- `adr-summary` — ADR 목록 + 요약
- `release-notes` — 지정 기간의 변경 페이지 요약
- `qa-export` — 축적된 Q&A 지식을 별도 문서로

### `qmd-index` — qmd 인덱스 (선택)

**실행**: `scripts/qmd_index.sh`

qmd 설치 전제. 없으면 설치 안내 후 exit 1.

### `lancedb-sync` — LanceDB 벡터 인덱스 (선택)

**실행**: `scripts/lancedb_sync.py`

`pip install lancedb duckdb sentence-transformers` 전제. 없으면 설치 안내 후 exit 1. 상세는 [lancedb-integration.md](references/lancedb-integration.md).

## Graceful Degrade 원칙

- `query`는 항상 작동 (qmd 있으면 하이브리드, 없으면 INDEX.md 라우팅)
- 명시 명령(`qmd-index`, `lancedb-sync`)은 의존성 없으면 설치 안내 + exit 1
- `init`은 환경을 감지만 할 뿐 종료 코드에 영향 없음

## 통합 포인트

### 다른 스킬과의 관계

- `qa-merge`: Q&A 카드 통합 결과를 `wiki/raw/`로 드롭 → 자동 ingest 대상
- `intent`: `INTENT.md` 변경 시 `raw/`로 복사 후 ingest → Why/What/Not/Learnings가 decision·entity 페이지로 분해
- `korean-docs`: 한국어 출력 규칙과 직교. 위키 페이지 식별자는 영어 허용 (Obsidian 호환)

### Obsidian

`wiki/`를 Obsidian vault로 열면:
- 그래프 뷰로 교차 참조 시각화
- `[[wiki-link]]` 네이티브 네비게이션
- 마크다운 실시간 프리뷰

## Karpathy 원칙 준수

- `raw/`는 LLM이 수정하지 않음 (read-only for wiki purposes)
- `wiki/*.md`는 LLM이 증분 갱신 (컴파일)
- CLAUDE.md가 스키마·컨벤션을 정의
- 3가지 연산(Ingest/Query/Lint)이 핵심, 나머지는 보조

## References (Progressive Disclosure)

- [page-templates.md](references/page-templates.md) — 6개 페이지 유형 템플릿
- [ingest-workflow.md](references/ingest-workflow.md) — Ingest 5단계 상세
- [claude-md-block.md](references/claude-md-block.md) — CLAUDE.md 추가 블록 템플릿
- [qmd-integration.md](references/qmd-integration.md) — qmd 설치·설정·MCP
- [lancedb-integration.md](references/lancedb-integration.md) — LanceDB + Embedding Atlas (Phase 3)
- [karpathy-pattern.md](references/karpathy-pattern.md) — 원본 패턴 + 본 구현 결정 기록

## Anti-patterns

- `wiki/index.md` 수동 편집 (sync에 덮어씌워짐)
- `wiki/raw/`의 원본 수정 (불변 원칙 위반 — 새 버전을 새 파일로 드롭)
- 페이지 제목에 한국어 공백 (Obsidian `[[link]]` 호환성 저하 — slug는 영어/하이픈 권장)
- 모순되는 정보를 두 페이지에 분산 (합성하여 단일 페이지로 정리하는 것이 위키의 목적)
```

- [ ] **Step 2: Verify line count**

```bash
wc -l plugins/documentation/skills/llm-wiki/SKILL.md
```
Expected: ≤300. If over, trim examples or move details to references.

- [ ] **Step 3: Run tests**

```bash
npm test
```
Expected: green.

- [ ] **Step 4: Commit**

```bash
git add plugins/documentation/skills/llm-wiki/SKILL.md
git commit -m "feat(llm-wiki): write 8-command orchestrator SKILL.md (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

---

## Stage F — Integration

### Task F1: Root README.md

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add llm-wiki row**

Locate `### Documentation` section. Add row to the table:

```markdown
| [llm-wiki](plugins/documentation/skills/llm-wiki) | Karpathy LLM Wiki 패턴 - 프로젝트 문서를 컴파일 위키로 유지 (qmd 하이브리드 검색, Obsidian 호환) |
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs(readme): list llm-wiki skill in Documentation section (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

### Task F2: plugins/documentation/README.md

**Files:**
- Modify: `plugins/documentation/README.md`

- [ ] **Step 1: Add llm-wiki content**

- Skills 테이블에 새 행:

```markdown
| [llm-wiki](skills/llm-wiki) | Karpathy LLM Wiki 패턴으로 프로젝트 문서를 컴파일 위키로 유지 | "위키 초기화", "wiki ingest", "프로젝트 컨텍스트 위키", "knowledge base 구축" |
```

- 특징 bullets에 추가:

```markdown
- **지식 컴파일** — `llm-wiki`가 Karpathy LLM Wiki 패턴으로 프로젝트 문서를 `wiki/`에 교차참조 마크다운으로 컴파일합니다. RAG 재검색이 아닌 복리 축적 모델.
```

- "5개 스킬" 같은 카운트 업데이트 (4 → 5)

- 사용 예시에 추가:

```markdown
### 예시 N — 프로젝트 지식을 위키로 컴파일
`llm-wiki init`으로 `wiki/` 구조를 생성하고 기존 문서를 `wiki/raw/`에 드롭한 뒤 `llm-wiki ingest`로 컴파일합니다. qmd 설치 시 하이브리드 검색이, LanceDB 설치 시 벡터 시각화(Embedding Atlas)가 자동 활성됩니다.
```

- [ ] **Step 2: Commit**

```bash
git add plugins/documentation/README.md
git commit -m "docs(documentation): add llm-wiki to plugin README (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

### Task F3: CHANGELOG.md

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add Unreleased entry**

Under `[Unreleased]` → `### Added`:

```markdown
- **llm-wiki** (documentation): Karpathy LLM Wiki 패턴 구현 스킬. 8개 서브커맨드(init/ingest/query/lint/sync/export/qmd-index/lancedb-sync). qmd 설치 시 하이브리드 검색 자동 활성, 미설치 시 INDEX.md 라우팅으로 graceful degrade. LanceDB + Embedding Atlas 선택적 벡터 인덱스 지원. Obsidian 호환 `[[wiki-link]]`. 워크스페이스 CLAUDE.md "LLM Wiki 활용 규칙"과 통합. (#8)
```

- [ ] **Step 2: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): note llm-wiki skill (#8)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

---

## Stage G — Verification

### Task G1: End-to-end sanity test

- [ ] **Step 1: Test init + sync + lint roundtrip**

```bash
cd /tmp && rm -rf llm-wiki-e2e && mkdir llm-wiki-e2e && cd llm-wiki-e2e

SKILL=/Users/dohyunjung/Workspace/roboco-io/tools/plugins/plugins/documentation/skills/llm-wiki

# init
"$SKILL/scripts/init.sh"

# Add test pages
cat > wiki/alpha.md <<'EOF'
---
title: Alpha
type: concept
tags: [core]
status: active
updated: 2026-04-19
---
# Alpha
Related: [[beta]]
EOF
cat > wiki/beta.md <<'EOF'
---
title: Beta
type: decision
status: active
updated: 2026-04-19
confidence: high
---
# Beta
Depends on [[alpha]]
EOF

# sync
python3 "$SKILL/scripts/sync_index.py"
cat wiki/index.md

# lint (should pass — both pages referenced in index + cross-ref)
python3 "$SKILL/scripts/lint_wiki.py"

# Break link to trigger lint issue
cat >> wiki/alpha.md <<'EOF'

See [[nonexistent]] too.
EOF
python3 "$SKILL/scripts/lint_wiki.py"
echo "lint exit code: $?"

cd && rm -rf /tmp/llm-wiki-e2e
```

Expected:
- init creates wiki structure + CLAUDE.md
- sync creates index.md with 2 pages grouped by type
- First lint passes (exit 0)
- Second lint catches `[[nonexistent]]` broken link (exit 1)

- [ ] **Step 2: Test qmd/LanceDB graceful degrade**

```bash
# qmd_index when qmd missing (if applicable)
if ! command -v qmd >/dev/null 2>&1; then
  $SKILL/scripts/qmd_index.sh /tmp/test-wiki
  echo "exit code: $?"  # expect 1 with install guidance
fi

# lancedb_sync when deps missing (likely)
python3 $SKILL/scripts/lancedb_sync.py --wiki-dir /tmp/test-wiki
echo "exit code: $?"  # expect 1 with pip install guidance
```

Expected: both exit 1 with clear install guidance.

### Task G2: Tests + final verification

- [ ] **Step 1: Full test suite**

```bash
cd /Users/dohyunjung/Workspace/roboco-io/tools/plugins
npm test
```
Expected: all tests pass.

- [ ] **Step 2: Line count checks**

```bash
wc -l plugins/documentation/skills/llm-wiki/SKILL.md
wc -l plugins/documentation/skills/llm-wiki/references/*.md
```
Expected: SKILL.md ≤300; references reasonable (≤400 each).

### Task G3: Push + PR

- [ ] **Step 1: Push branch**

```bash
git push -u origin feat/issue-8-llm-wiki
```

- [ ] **Step 2: Create PR**

```bash
gh pr create --base main --head feat/issue-8-llm-wiki --title "feat(documentation): add llm-wiki skill (Karpathy + qmd) (#8)" --body "$(cat <<'EOF'
## Summary

Karpathy LLM Wiki 패턴을 구현한 `llm-wiki` 스킬을 `documentation` 플러그인에 추가합니다.

- 8개 서브커맨드: `init`, `ingest`, `query`, `lint`, `sync`, `export`, `qmd-index`, `lancedb-sync`
- qmd 감지 시 하이브리드 검색 자동 활성, 미감지 시 INDEX.md 라우팅으로 graceful degrade
- LanceDB + Embedding Atlas 선택적 벡터 인덱스 (Phase 3)
- `wjtb-cmc/.claude/skills/llm-wiki/` 포팅 + 일반화 (LEP-특수 제거, `.wiki/` → `wiki/`)
- 워크스페이스 CLAUDE.md "LLM Wiki 활용 규칙"과 통합

## Changes

- 새 스킬 `plugins/documentation/skills/llm-wiki/`
  - SKILL.md (≤300 lines)
  - references/ 6개 (page-templates, ingest-workflow, claude-md-block, qmd-integration, lancedb-integration, karpathy-pattern)
  - scripts/ 5개 (init.sh, sync_index.py, lint_wiki.py, qmd_index.sh, lancedb_sync.py)
- `.claude-plugin/marketplace.json` 등록
- root README, `plugins/documentation/README.md`, CHANGELOG 업데이트
- 설계 문서: `issues/8-llm-wiki/SPEC.md`, `PLAN.md`, `TASKS.md`

## Closes

- #8

## Test plan

- [x] `npm test` 전부 green
- [x] E2E: init + sync + lint 라운드트립 통과
- [x] qmd/LanceDB graceful degrade 동작
- [ ] 로컬 설치 후 실제 프로젝트에서 ingest 시나리오 검증

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review

**Spec coverage:**

| SPEC § | Task |
|--------|------|
| §2.1 Directory layout | B1 |
| §3 Commands (8개) | E1 (SKILL.md inline), scripts in C |
| §4 Graceful degrade | C4, C5 (install guidance), E1 (SKILL body) |
| §5 References 6개 | D1-D6 |
| §6 Scripts 5개 | C1-C5 |
| §7 Integration points | E1 (SKILL.md integration section) |
| §8 Obsidian compat | E1, D1 (page-templates) |
| §9 Citation rules | applied in references inline |
| §10 Non-goals | E1 inline |
| §11 Success criteria | G1 E2E test |
| §12 Decisions summary | D6 karpathy-pattern.md |

**Placeholder scan:** No TBD/TODO left in the plan. All code blocks complete.

**Type consistency:**
- `wiki/` used consistently (not `.wiki/`)
- `parse_frontmatter` function matches in sync_index.py and lint_wiki.py (both stdlib-only)
- Command names consistent: `init/ingest/query/lint/sync/export/qmd-index/lancedb-sync`

---

## Execution Handoff

Plan complete and saved to `issues/8-llm-wiki/TASKS.md`. Two execution options:

**1. Subagent-Driven (recommended)** — dispatch fresh subagent per Stage, review between stages.

**2. Inline Execution** — execute in current session with stage checkpoints.

Awaiting user decision.
