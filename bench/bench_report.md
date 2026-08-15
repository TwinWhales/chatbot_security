# forensicagent RAG benchmark

- cases: **14** | tools: **11** | k: [3, 5] | RAG reranked 2/14 cases
- LLM modes not requested (--with-llm off).

## Aggregate (mean over cases)

| metric | deterministic | rag |
|---|---|---|
| ndcg@3 | 0.9295 | 0.9422 |
| ndcg@5 | 0.9485 | 0.9613 |
| mrr | 1.0000 | 1.0000 |
| core_mrr | 0.8929 | 0.9286 |
| p@3 | 0.6429 | 0.6429 |
| p@5 | 0.4143 | 0.4143 |
| r@3 | 0.9714 | 0.9714 |
| r@5 | 1.0000 | 1.0000 |
| core_r@3 | 0.9524 | 0.9524 |
| core_r@5 | 1.0000 | 1.0000 |

## Delta: rag_vs_deterministic (positive = RAG better)

| metric | delta |
|---|---|
| ndcg@3 | +0.0127 |
| ndcg@5 | +0.0128 |
| mrr | 0.0000 |
| core_mrr | +0.0357 |
| p@3 | 0.0000 |
| p@5 | 0.0000 |
| r@3 | 0.0000 |
| r@5 | 0.0000 |
| core_r@3 | 0.0000 |
| core_r@5 | 0.0000 |

## Timing (mean ms per case)

| mode | select_filter | select_rag | select_rank |
|---|---|---|---|
| deterministic | 0.0 | 0.0 | 0.0 |
| rag | 0.0 | 4355.4 | 0.0 |

## Per-case (deterministic vs rag)

| case | elig | scen | det ndcg@3 | rag ndcg@3 | delta | rag order (top4) |
|---|---|---|---|---|---|---|
| logon-bruteforce-evtx | 2 | Y | 1.000 | 1.000 | +0.000 | chainsaw > evtxecmd |
| powershell-scriptblock | 2 | Y | 1.000 | 1.000 | +0.000 | chainsaw > evtxecmd |
| evtx-service-install | 2 | Y | 1.000 | 1.000 | +0.000 | chainsaw > evtxecmd |
| evtx-no-scenario | 2 | - | 1.000 | 1.000 | +0.000 | chainsaw > evtxecmd |
| registry-runkey-persistence | 2 | Y | 1.000 | 1.000 | +0.000 | recmd > regripper |
| amcache-program-execution | 1 | Y | 1.000 | 1.000 | +0.000 | amcacheparser |
| registry-usb-history | 2 | Y | 0.797 | 0.797 | +0.000 | recmd > regripper |
| memory-implant-triage | 1 | Y | 1.000 | 1.000 | +0.000 | volatility3 |
| prefetch-execution-timeline | 1 | Y | 1.000 | 1.000 | +0.000 | pecmd |
| disk-mft-timeline | 1 | Y | 1.000 | 1.000 | +0.000 | mftecmd |
| python-vuln-scan | 3 | Y | 0.951 | 0.951 | +0.000 | semgrep > gitleaks > bandit |
| secrets-leak-scan | 3 | Y | 0.821 | 1.000 | +0.179 | gitleaks > semgrep > bandit |
| js-security-audit | 2 | Y | 0.797 | 0.797 | +0.000 | gitleaks > semgrep |
| mixed-intrusion-triage | 5 | Y | 0.646 | 0.646 | +0.000 | chainsaw > evtxecmd > recmd > regripper |

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
