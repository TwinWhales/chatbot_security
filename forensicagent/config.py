"""Global configuration for forensicagent.

All tunable parameters live here so individual modules stay declarative.
Resolution order for every value below:

  1. process env var (highest — wins even if .env disagrees)
  2. `.env` file (loaded once at import time)
  3. hard-coded default in this module

The `.env` lookup itself is also overridable: set ``FORENSICAGENT_DOTENV``
to a specific file path, otherwise we try ``$PROJECT_ROOT/.env`` then
``$CWD/.env``.  Missing files are silently skipped — .env is optional.
"""

from __future__ import annotations

import os
from pathlib import Path


# === Project paths (absolute, derived from this file's location) ===
PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# .env loading — run BEFORE any os.getenv() call below.
# ---------------------------------------------------------------------------
def _load_dotenv_if_present() -> None:
    """Best-effort load of a .env file. Never raises; never overrides real env."""
    try:
        from dotenv import load_dotenv  # type: ignore[import-not-found]
    except ImportError:
        return  # python-dotenv missing — fall back to env vars + defaults only.

    explicit = os.getenv("FORENSICAGENT_DOTENV")
    candidates = [Path(explicit)] if explicit else [
        PROJECT_ROOT / ".env",
        Path.cwd() / ".env",
    ]
    for p in candidates:
        if p.is_file():
            # override=False → real shell env wins over .env (POSIX convention).
            load_dotenv(p, override=False)
            return


_load_dotenv_if_present()


# ---------------------------------------------------------------------------
# Helper: resolve a path-valued setting to an absolute Path.
# Relative entries in .env are interpreted relative to PROJECT_ROOT (NOT cwd),
# so the agent behaves identically no matter where you launch it from.
# ---------------------------------------------------------------------------
def _abs_path(env_name: str, default: Path) -> Path:
    raw = os.getenv(env_name)
    if not raw:
        return default
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = (PROJECT_ROOT / p).resolve()
    return p


# === Per-user state directory (defaults outside the repo) ===
USER_HOME = _abs_path("FORENSICAGENT_HOME", Path.home() / ".forensicagent")

# === Tool metadata YAMLs ===
TOOLS_METADATA_DIR = _abs_path("FORENSICAGENT_TOOLS_DIR", USER_HOME / "tools")


def resolve_tools_dir() -> Path:
    """Canonical tool-YAML directory resolution — shared by EVERY entry point.

    모든 곳(tools list / doctor / rag index-tools / selector·analyzer 런타임
    로드)이 이 함수를 거쳐 동일하게 해석한다. 우선순위:

      1. FORENSICAGENT_TOOLS_DIR env  ┐ (둘 다 TOOLS_METADATA_DIR 에 반영됨)
      2. ~/.forensicagent/tools       ┘
      3. repo PROJECT_ROOT/tools_metadata   (어느 cwd 에서 실행하든 리포 자산 사용)
      4. cwd/tools_metadata

    *.yaml/*.yml 이 실제로 들어있는 첫 후보를 반환. 아무 곳에도 없으면
    1 번(primary)을 그대로 반환 → 호출자가 '비어있음' 을 감지해 안내.
    """
    primary = Path(TOOLS_METADATA_DIR)
    if primary.exists() and any(primary.glob("*.y*ml")):
        return primary
    for fallback in (PROJECT_ROOT / "tools_metadata", Path.cwd() / "tools_metadata"):
        if fallback.exists() and any(fallback.glob("*.y*ml")):
            return fallback
    return primary

# === ChromaDB persistence ===
CHROMA_PERSIST_DIR = str(_abs_path("FORENSICAGENT_CHROMA_DIR", USER_HOME / "chroma"))
CHROMA_COLLECTION = os.getenv("FORENSICAGENT_COLLECTION", "forensic_tools")

# Dedicated collection holding the tool-metadata corpus (one doc per tool).
# This is what the runtime Selector queries for RAG-based ranking — kept
# separate from the crawled seed_docs collections (seed_*).
TOOL_COLLECTION = os.getenv("FORENSICAGENT_TOOL_COLLECTION", "forensic_tool_meta")


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on", "y")


# === Runtime RAG (tool selection + analyzer context) ===
# USE_RAG is the *intent* flag (default on). Actual availability is checked
# lazily at query time — if chromadb / sentence-transformers / the model /
# the index are missing, the runtime silently falls back to the deterministic
# + LLM path. So turning this on never breaks a run that lacks the deps.
USE_RAG = _env_bool("FORENSICAGENT_USE_RAG", True)
RAG_TOP_K = int(os.getenv("FORENSICAGENT_RAG_TOP_K", "5"))

# === Crawled corpus root (used by rag.indexer) ===
SEED_DOCS_DIR = _abs_path("FORENSICAGENT_SEED_DOCS_DIR", PROJECT_ROOT / "seed_docs")

# === Default output dir ===
# If user sets FORENSICAGENT_OUTPUT_DIR (abs or rel-to-PROJECT_ROOT) we use
# that directly. Otherwise we leave OUTPUT_DIR_NAME as a relative name that
# CLI helpers join with the *current evidence cwd* so each case gets its own
# output sibling — the historical default.
_OUTPUT_DIR_RAW = os.getenv("FORENSICAGENT_OUTPUT_DIR")
if _OUTPUT_DIR_RAW:
    _p = Path(_OUTPUT_DIR_RAW).expanduser()
    if not _p.is_absolute():
        _p = (PROJECT_ROOT / _p).resolve()
    OUTPUT_DIR: Path | None = _p
    OUTPUT_DIR_NAME = _p.name
else:
    OUTPUT_DIR = None
    OUTPUT_DIR_NAME = "forensicagent_output"


def default_output_dir(working_dir: Path | None = None) -> Path:
    """Resolve the default output directory.

    * If FORENSICAGENT_OUTPUT_DIR was set, return it (absolute).
    * Otherwise join `OUTPUT_DIR_NAME` to ``working_dir`` (or cwd).
    """
    if OUTPUT_DIR is not None:
        return OUTPUT_DIR
    base = (working_dir or Path.cwd()).resolve()
    return (base / OUTPUT_DIR_NAME).resolve()


# === Embedding settings ===
# Tool YAML descriptions get embedded into a small, single-language-friendly model.
# Override with FORENSICAGENT_EMBEDDING_MODEL=BAAI/bge-m3 for multilingual.
EMBEDDING_MODEL = os.getenv(
    "FORENSICAGENT_EMBEDDING_MODEL",
    "sentence-transformers/all-MiniLM-L6-v2",
)

# === LLM (Ollama) settings ===
LLM_PROVIDER = os.getenv("FORENSICAGENT_LLM_PROVIDER", "ollama")
LLM_BASE_URL = os.getenv("FORENSICAGENT_LLM_BASE_URL", "http://localhost:11434")
LLM_MODEL = os.getenv("FORENSICAGENT_LLM_MODEL", "qwen2.5:14b")
LLM_TEMPERATURE = float(os.getenv("FORENSICAGENT_LLM_TEMPERATURE", "0.1"))

# === Execution settings ===
DEFAULT_TIMEOUT_SEC = int(os.getenv("FORENSICAGENT_TIMEOUT_SEC", "300"))
MAX_PARALLEL_TOOLS = int(os.getenv("FORENSICAGENT_MAX_PARALLEL", "3"))

# === Optional API keys (for OpenAI embedding backend, if user opts in) ===
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
