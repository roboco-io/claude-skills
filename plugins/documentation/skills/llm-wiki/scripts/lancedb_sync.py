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
        missing = getattr(e, 'name', 'unknown')
        print(f"error: 필수 의존성 누락 ({missing}). 설치:", file=sys.stderr)
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
        rel_parts = md.relative_to(wiki_dir).parts
        if 'raw' in rel_parts:
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
            'text': body[:10000],
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
