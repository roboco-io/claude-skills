#!/usr/bin/env python3
"""Rebuild wiki/index.md by scanning wiki/*.md for frontmatter and links.

Usage:
    ./sync_index.py [--wiki-dir PATH]

Default --wiki-dir is ./wiki relative to CWD.
Zero-dependency (stdlib only).
"""
import argparse
import re
import sys
from pathlib import Path
from collections import defaultdict

FRONTMATTER_RE = re.compile(r'\A---\n(.*?)\n---\n', re.DOTALL)


def parse_frontmatter(text):
    """Minimal zero-dep YAML-ish frontmatter parser.

    Supports: key: value, key: [a, b, c] (inline list), key: "quoted value".
    Does NOT support: nested dicts, block lists, multi-line scalars.
    """
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}
    result = {}
    for line in m.group(1).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
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
    """Scan wiki_dir for *.md (excluding index.md, log.md, raw/ subtree)."""
    pages = []
    for md in wiki_dir.rglob('*.md'):
        if md.name in ('index.md', 'log.md'):
            continue
        rel_parts = md.relative_to(wiki_dir).parts
        if 'raw' in rel_parts:
            continue
        text = md.read_text(encoding='utf-8')
        fm = parse_frontmatter(text)
        tags_field = fm.get('tags', [])
        if isinstance(tags_field, str):
            tags = [tags_field] if tags_field else []
        elif isinstance(tags_field, list):
            tags = tags_field
        else:
            tags = []
        pages.append({
            'path': md.relative_to(wiki_dir),
            'title': fm.get('title', md.stem),
            'type': fm.get('type', 'page'),
            'tags': tags,
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
    parser.add_argument('--wiki-dir', default='./wiki',
                        help='wiki directory (default ./wiki)')
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
