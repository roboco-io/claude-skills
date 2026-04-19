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

6개 도구 노출: `query`, `search`, `vsearch`, `get`, `multi-get`, `status`. HTTP 데몬 모드에서 LLM 모델이 VRAM에 유지되어 반복 호출 지연 최소화.

## 위키 인덱싱

llm-wiki `qmd-index` 명령이 내부적으로 실행:

```bash
qmd index wiki/
qmd context add qmd://wiki "LLM Wiki: 프로젝트 컨텍스트 위키 (Karpathy 패턴)"
```

수동 실행도 동일. 인덱스는 `~/.qmd/indexes/`에 저장됨 (qmd 기본).

## 검색 모드

| 모드 | CLI | 설명 | 속도 |
|------|-----|------|------|
| search | `qmd search "rate limit"` | BM25 키워드 매칭 | ~132ms |
| vsearch | `qmd vsearch "throttling patterns"` | 벡터 시맨틱 | ~2.9초 |
| query | `qmd query "API 제한 패턴"` | 하이브리드 (FTS + vec + LLM 재순위) | ~17-20초 |

llm-wiki의 `query` 명령은 내부적으로 `qmd query`를 호출 (qmd 감지 시).

## 다국어 지원

한국어/일본어는 기본 모델(`embeddinggemma-300M`)로도 동작. 품질 향상 원하면:

```bash
export QMD_EMBED_MODEL=Qwen3-Embedding-0.6B
qmd index wiki/  # 재인덱싱
```

## 컨텍스트 트리

qmd의 킬러 피처. 컬렉션별 설명을 추가하면 검색 결과에 컨텍스트가 함께 반환되어 LLM이 문서 위치를 이해:

```bash
qmd context add qmd://wiki "프로젝트 컨텍스트 위키"
qmd context add qmd://wiki/decisions "아키텍처 결정 기록 (ADR)"
qmd context add qmd://wiki/meetings "회의록 요약"
```

## 스마트 청킹

qmd는 마크다운 헤딩·코드 블록·빈 줄에서 자동 분할, 타겟 ~900 토큰 + 15% 오버랩. 코드 블록은 중간 분할 금지. 별도 설정 불필요.

## lazyqmd (TUI)

Alexander Zeitler의 터미널 UI. Ctrl+T로 search/vsearch/query 모드 전환.

```bash
bun install -g lazyqmd
```

## Reference links

- qmd: https://github.com/tobi/qmd
- lazyqmd: https://github.com/alexanderzeitler/lazyqmd
- Karpathy LLM Wiki: https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f
