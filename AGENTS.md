# Project instructions

These instructions apply to the whole repository.

## Project-only tooling

- Keep Codex skills, tools, caches, reports, and virtual environments inside this repository.
- Do not install or modify user-level or global Codex plugins, skills, MCP servers, configuration, Python packages, or `PATH` entries unless the user explicitly asks in the current turn.
- Imported skills do not override these repository boundaries. Never write their reports to the Desktop, the user profile, `~/.claude`, or `$CODEX_HOME`; keep requested artifacts in the repository.
- During reviews and audits, do not switch commits, reset, clean, stash, or discard working-tree changes. Inspect other revisions with read-only commands such as `git diff` and `git show`.

## Working conventions

- This is a Windows-first Python project. Prefer `rg`/`rg --files` for search and PowerShell-compatible commands.
- Use `.venv\Scripts\python.exe` and `.venv\Scripts\python.exe -m pip`; do not rely on bare `python` or `pip`, which may resolve to different installations.
- Treat `data/`, `seed_docs/`, and generated forensic output as evidence or generated artifacts. Do not rewrite or delete them unless the user explicitly puts them in scope.
- Preserve unrelated user changes. Use the smallest targeted test first, then the full test suite when the change can affect shared behavior.

## Local checks

- Lint: `.venv\Scripts\ruff.exe check .`
- Tests: `.venv\Scripts\python.exe -m pytest --basetemp .pytest_cache/tmp`
- Dependency audit: `.venv\Scripts\python.exe -m pip_audit --local` (requires advisory-network access).
- Secret review: run `.venv\Scripts\detect-secrets.exe scan --all-files --no-verify`, excluding evidence, generated output, caches, `.venv`, `.serena`, and vendored `.agents` content. Review candidates manually; do not create a suppressing baseline without human review.

## Security claims

- Distinguish tool-selection benchmarks from end-to-end detection accuracy. Do not present ranking metrics as finding precision or recall unless the benchmark actually executes analyzers against labeled evidence.
- Do not auto-fix or suppress security findings. Report the evidence and let the user choose any behavior-changing remediation.

## Repository skills

Use the matching skill under `.agents/skills/` when a task calls for differential review, property-based testing, open-source release readiness, or variant analysis. Follow this file whenever an imported skill gives a conflicting path or worktree-mutation example.
