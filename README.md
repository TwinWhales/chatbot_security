# RAG (Retrieval-Augmented Generation) System

5-layer RAG pipeline implemented as two **LangGraph StateGraphs** (one for
ingestion, one for query). Falls back to web search when the top similarity
score is below the configured threshold.

자세한 한국어 설계 문서는 [`CLAUDE.md`](CLAUDE.md) 와 각 디렉토리의
`CLAUDE.md` 참고.

## Layers

| Layer | Path | Purpose |
| --- | --- | --- |
| 1 — Data Ingestion | `src/ingestion/` | upload → extract → OCR → clean → chunk → embed → tag → store |
| 2 — Query Processing | `src/query/` | preprocess → embed |
| 3 — Knowledge Engine | `src/knowledge/` | vector store, knowledge base, top-K retrieval + threshold |
| 4 — Response Intelligence | `src/response/` | RAG path / web-search fallback / final answer + citations |
| 5 — Logging | `src/logging/` | every Q/A cycle persisted to SQL for future learning |
| (cross-cutting) | `src/observability/` | Stopwatch + Metrics dataclasses + percentiles |
| (orchestration) | `src/graphs/` | LangGraph StateGraphs that wire the layers together |

## Install

```bash
pip install -r requirements.txt
```

OCR additionally needs the Tesseract binary on `PATH` (or set `TESSERACT_CMD`).

## Configure

Defaults live in `config/settings.py`. Anything that varies per environment
can be overridden via env vars — common ones:

```
ANTHROPIC_API_KEY=...    # required for Path A LLM answers
TAVILY_API_KEY=...       # required for Path B web fallback
EMBEDDING_MODEL=jhgan/ko-sroberta-multitask
SIMILARITY_THRESHOLD=0.7
TOP_K=5
```

Without an LLM key the response layer returns a stub answer so the pipeline
still completes end-to-end.

## Use

```bash
python main.py ingest path/to/doc.pdf
python main.py ask "2024년 3분기 매출 실적은?"
python main.py stats
```

`ask` accepts `--rewrite` (LLM query rewriting) and `--json` (machine output).
