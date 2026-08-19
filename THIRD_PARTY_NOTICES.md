# Third-party notices

The project-scoped Codex skills under `.agents/skills/` are unmodified copies from
[Trail of Bits Skills](https://github.com/trailofbits/skills) at commit
`4db56eff303d088c43b85c7b032f47e7b9ba862e`:

- `differential-review` — `plugins/differential-review/skills/differential-review`
- `open-sourcing` — `plugins/open-sourcing/skills/open-sourcing`
- `property-based-testing` — `plugins/property-based-testing/skills/property-based-testing`
- `variant-analysis` — `plugins/variant-analysis/skills/variant-analysis`

Copyright remains with Trail of Bits and the respective contributors. These files
are licensed under [Creative Commons Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/),
not the main project's MIT license. No endorsement by Trail of Bits is implied.

Source paths and complete revision history are available in the linked repository.

## Project-local development integration

[Serena 1.7.0](https://github.com/oraios/serena/releases/tag/v1.7.0) is configured
as a read-only Codex MCP server. Its source revision is
`949a27ef1e5fda1a6e7b561e777bcece345c6ffd` and it is licensed under the MIT
License. Serena is not vendored: `uvx` downloads it into the ignored `.serena/`
project cache.

The development extra also pins Ruff 0.16.0, pip-audit 2.10.1, and
detect-secrets 1.5.0. Those packages retain their respective upstream licenses.
