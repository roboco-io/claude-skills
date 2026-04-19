#!/usr/bin/env python3
"""Lint wiki/*.md for broken links, orphans, and missing frontmatter.

Usage:
    ./lint_wiki.py [--wiki-dir PATH]

Exit code 0 if clean, 1 if issues.
Zero-dependency (stdlib only).
"""
import argparse
import re
import sys
from pathlib import Path

WIKILINK_RE = re.compile(r'\[\[([^\]|]+)(?:\|[^\]]+)?\]\]')
FRONTMATTER_RE = re.compile(r'\A---\n(.*?)\n---\n', re.DOTALL)
REQUIRED_FM = ['title', 'updated']


def parse_frontmatter(text):
    """Minimal zero-dep frontmatter parser (matches sync_index.py)."""
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}
    result = {}
    for line in m.group(1).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or ':' not in line:
            continue
        k, v = line.split(':', 1)
        k = k.strip()
        v = v.strip()
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        result[k] = v
    return result


def lint(wiki_dir):
    md_files = []
    for p in wiki_dir.rglob('*.md'):
        rel_parts = p.relative_to(wiki_dir).parts
        if 'raw' in rel_parts:
            continue
        md_files.append(p)

    page_stems = {
        p.stem for p in md_files
        if p.name not in ('index.md', 'log.md')
    }

    issues = []
    referenced = set()

    for md in md_files:
        text = md.read_text(encoding='utf-8')
        is_index_or_log = md.name in ('index.md', 'log.md')

        if not is_index_or_log:
            fm = parse_frontmatter(text)

            for field in REQUIRED_FM:
                if field not in fm or not fm[field]:
                    issues.append(
                        f"{md.relative_to(wiki_dir)}: frontmatter `{field}` missing"
                    )

            confidence_raw = fm.get('confidence', '')
            confidence = confidence_raw.lower() if isinstance(confidence_raw, str) else ''
            if confidence in ('low', 'tentative'):
                issues.append(
                    f"{md.relative_to(wiki_dir)}: low-confidence page flagged"
                )

        for link in WIKILINK_RE.findall(text):
            target = link.strip()
            if target not in page_stems:
                issues.append(
                    f"{md.relative_to(wiki_dir)}: broken link [[{target}]]"
                )
            elif not is_index_or_log:
                # Only count references from content pages toward orphan detection
                referenced.add(target)

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
        total = sum(1 for _ in wiki_dir.rglob('*.md'))
        print(f"✓ clean ({total} files)")
        return 0

    print(f"⚠ {len(issues)} issue(s):", file=sys.stderr)
    for issue in issues:
        print(f"  - {issue}", file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
