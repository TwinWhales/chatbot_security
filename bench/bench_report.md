# forensicagent RAG benchmark

- cases: **14** | tools: **11** | k: [3, 5] | RAG reranked 13/14 cases
- LLM modes enabled (qwen2.5:14b: ollama ok, model qwen2.5:14b ready (6 pulled)).
- index build: 11 tools, embed 24730ms, chroma 510ms, total 27.16s

## Aggregate (mean over cases)

| metric | deterministic | rag | llm | rag_llm |
|---|---|---|---|---|
| ndcg@3 | 0.8249 | 0.8644 | 0.8249 | 0.8644 |
| ndcg@5 | 0.8744 | 0.8647 | 0.8744 | 0.8647 |
| mrr | 0.9524 | 0.9643 | 0.9524 | 0.9643 |
| p@3 | 0.6429 | 0.7143 | 0.6429 | 0.7143 |
| p@5 | 0.4429 | 0.4429 | 0.4429 | 0.4429 |
| r@3 | 0.8810 | 0.9643 | 0.8810 | 0.9643 |
| r@5 | 0.9762 | 0.9762 | 0.9762 | 0.9762 |

## Delta: rag_vs_deterministic (positive = RAG better)

| metric | delta |
|---|---|
| ndcg@3 | +0.0395 |
| ndcg@5 | -0.0097 |
| mrr | +0.0119 |
| p@3 | +0.0714 |
| p@5 | 0.0000 |
| r@3 | +0.0833 |
| r@5 | 0.0000 |

## Delta: rag_llm_vs_llm (positive = RAG better)

| metric | delta |
|---|---|
| ndcg@3 | +0.0395 |
| ndcg@5 | -0.0097 |
| mrr | +0.0119 |
| p@3 | +0.0714 |
| p@5 | 0.0000 |
| r@3 | +0.0833 |
| r@5 | 0.0000 |

## Timing (mean ms per case)

| mode | select_filter | select_rag | select_rank |
|---|---|---|---|
| deterministic | 0.0 | 0.0 | 0.0 |
| rag | 0.0 | 46.7 | 0.0 |
| llm | 0.0 | 0.0 | 2720.7 |
| rag_llm | 0.0 | 29.1 | 2648.7 |

## Per-case (deterministic vs rag)

| case | elig | scen | det ndcg@3 | rag ndcg@3 | delta | rag order (top4) |
|---|---|---|---|---|---|---|
| logon-bruteforce-evtx | 2 | Y | 1.000 | 0.797 | -0.203 | evtxecmd > chainsaw |
| powershell-scriptblock | 2 | Y | 1.000 | 0.797 | -0.203 | evtxecmd > chainsaw |
| evtx-service-install | 2 | Y | 1.000 | 0.797 | -0.203 | evtxecmd > chainsaw |
| evtx-no-scenario | 2 | - | 1.000 | 0.797 | -0.203 | evtxecmd > chainsaw |
| registry-runkey-persistence | 4 | Y | 0.464 | 0.951 | +0.488 | regripper > amcacheparser > recmd > mftecmd |
| amcache-program-execution | 4 | Y | 0.847 | 1.000 | +0.153 | amcacheparser > recmd > regripper > mftecmd |
| registry-usb-history | 4 | Y | 0.138 | 0.659 | +0.521 | amcacheparser > regripper > recmd > mftecmd |
| memory-implant-triage | 1 | Y | 1.000 | 1.000 | +0.000 | volatility3 |
| prefetch-execution-timeline | 1 | Y | 1.000 | 1.000 | +0.000 | pecmd |
| disk-mft-timeline | 1 | Y | 1.000 | 1.000 | +0.000 | mftecmd |
| python-vuln-scan | 3 | Y | 0.951 | 0.815 | -0.137 | gitleaks > semgrep > bandit |
| secrets-leak-scan | 3 | Y | 0.821 | 1.000 | +0.179 | gitleaks > semgrep > bandit |
| js-security-audit | 2 | Y | 0.797 | 1.000 | +0.203 | semgrep > gitleaks |
| mixed-intrusion-triage | 7 | Y | 0.531 | 0.490 | -0.041 | amcacheparser > recmd > regripper > evtxecmd |

## Methodology

- **Goal**: quantify how much RAG reranking improves the Selector's tool
  *ordering* over a deterministic-only baseline.
- **Golden set**: 14 SYNTHETIC, hand-labeled English cases (one labeler).
  Each case = an evidence inventory (evidence_type + filenames) + optional
  English scenario + per-tool relevance grades (2=core, 1=secondary,
  0=irrelevant-but-eligible). NOT real CTF data.
- **Qualification is identical across modes**: the deterministic evidence-type
  gate (Stage 1) admits the same tool set in every mode, so all differences
  below come purely from ORDERING, never from which tools qualify.
- **Baseline (deterministic)**: `use_rag=False, use_llm=False` -> Stage 1
  filter order (tool_metadata load order), which carries no semantic signal.
- **RAG**: `use_rag=True, use_llm=False` -> candidates reranked by cosine
  similarity of the tool-metadata corpus to an (evidence + scenario) query,
  embedded with all-MiniLM-L6-v2.
- **Metrics**: NDCG@k uses exponential gain (2^rel - 1)/log2(rank+1); MRR,
  Precision@k, Recall@k use relevance >= 1 as the "relevant" threshold.
  k in [3, 5]. Reported values are means across cases.

## Limitations (read before trusting the numbers)

- Small (n=14), synthetic, single-labeler golden set - indicative, not
  statistically robust. Labels encode one analyst's judgement.
- Only 11 tools; several evidence types map to a single eligible tool,
  where ordering is trivial (metric == 1.0 regardless of mode) and dilutes the
  measured delta. The signal lives in multi-tool cases (registry_hive,
  evtx_log, source_code_*).
- all-MiniLM-L6-v2 is English-centric; this bench is English on purpose. Korean
  scenarios would score worse (swap FORENSICAGENT_EMBEDDING_MODEL for bge-m3).
- Ordering quality only. This does NOT measure end-to-end triage correctness,
  tool execution, or finding quality.
- RAG safety property (never promotes a tool outside Stage 1) and graceful
  fallback are covered by unit tests, not by this benchmark.
