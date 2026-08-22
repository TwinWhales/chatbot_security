# Differential Review Report

## Scope

- Baseline: `288dff3` (`ai_native` HEAD)
- Reviewed: current unstaged working-tree changes
- Size: 26 tracked files, `+795/-123`, plus `tests/test_llm_grounding.py`
- Strategy: focused review of the analyzer, executor, reporter, UI trust boundary,
  tool metadata, and changed tests
- Excluded: `test_evi/` (known-malicious evidence; not opened or executed)

The change is high-risk by area because it changes finding identity, LLM input,
event-log validation, and report rendering. The event namespace checks and
generated-output dependency exclusion are sound improvements. The main issues
are an LLM budget regression and compatibility at the persistent annotation
boundary.

## Findings

### P1 / Medium — Grounding IDs bypass the configured LLM character budget

Location: `forensicagent/analyzer/llm_extract.py:155-156`

`raw_text` is first truncated to `budget_chars`, but `_grounding_payload()` then
adds a roughly 30-character prefix to every non-empty line. Consequently the
actual prompt is not bounded by `budget_chars`. A 12,000-character input made of
short lines expands to 215,999 characters (18x) in the current implementation.

Impact:

- ordinary short-row CSV/text output can become much slower on local Ollama;
- the prompt can exceed the intended context budget and fail or time out;
- attacker-controlled tool output can amplify LLM work and create an
  availability problem.

Recommendation: enforce the budget on the final rendered grounding payload, or
use compact ordinal IDs and reserve their overhead before truncation. Add a test
asserting that the final user payload remains within a defined ceiling for many
short lines.

### P2 / Medium — Every existing finding fingerprint changes, orphaning annotations

Locations:

- `forensicagent/analyzer/types.py:72-82`
- `forensicagent/reporter/reporter.py:60-66`

The fingerprint canonical object now always contains `evidence_id`, `channel`,
and `provider`, including when all three are empty. Adding those empty keys
changes the SHA-256 for every legacy finding, not only Windows event findings.
The reporter only attaches stored annotations whose key matches a current
fingerprint, so all previous `confirmed` / `false_positive` / notes entries
become stale after this update.

Impact: analysts lose annotation continuity on reruns of unchanged evidence.
Annotations do not suppress findings, so this is an operational integrity issue
rather than silent finding loss.

Recommendation: either preserve the legacy fingerprint payload, introduce a
versioned fingerprint with migration/dual lookup, or explicitly treat this as a
breaking schema migration. Add a test that loads a pre-change annotation for an
unchanged non-event finding.

### P3 / Low — The shared terminal sanitizer now permits layout injection

Location: `forensicagent/ui_text.py:8-12`

The previous sanitizer, introduced in security-hardening commit `be97e92`,
replaced all C0 controls. The new implementation preserves newline, carriage
return, and tab for every call site. Rich removes carriage return in the tested
plain console path, but newlines and tabs remain and can let untrusted tool/LLM
text create additional terminal lines that resemble surrounding status output.

Recommendation: keep single-line sanitization as the default and opt into
multiline layout only for explicit narrative/panel contexts.

## Blast Radius

- Event identity/context helpers feed 8 runtime `_event_id()` call sites and all
  Windows event correlation rules.
- `Finding.refresh_fingerprint()` feeds deduplication, report annotations,
  timeline/correlation references, and CLI annotation lookup.
- `safe_text()` is the common terminal trust boundary across CLI, REPL, UI, and
  terminal reports.
- `_command_dependencies()` is executor-internal and its generated-directory
  exclusion is covered before and after output creation.

## Verification

- Changed-file Ruff check: passed.
- Full scoped Ruff check (`forensicagent tests bench scripts`): passed.
- Changed-area pytest selection: passed.
- Full `tests/` suite: passed; 3 symlink tests skipped because Windows symlink
  privileges are unavailable.
- `git diff --check`: passed (only expected LF-to-CRLF warnings).

No evidence files were executed and no production code was modified during the
review.
