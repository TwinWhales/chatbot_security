"""Global configuration for forensicagent.

All tunable parameters live here so individual modules stay declarative.
Environment variables (when set) take precedence over the defaults below;
the user's `~/.forensicagent/config.yaml` will override env vars once
the loader is implemented (Phase 1).
"""

from __future__ import annotations

import os
from pathlib import Path

# === Project paths ===
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Per-user state lives outside the repo so the agent works from any CWD.
USER_HOME = Path(os.getenv("FORENSICAGENT_HOME", str(Path.home() / ".forensicagent")))
TOOLS_METADATA_DIR = Path(
    os.getenv("FORENSICAGENT_TOOLS_DIR", str(USER_HOME / "tools"))
)
CHROMA_PERSIST_DIR = os.getenv(
    "FORENSICAGENT_CHROMA_DIR", str(USER_HOME / "chroma")
)
CHROMA_COLLECTION = os.getenv("FORENSICAGENT_COLLECTION", "forensic_tools")

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
OUTPUT_DIR_NAME = os.getenv("FORENSICAGENT_OUTPUT_DIR", "forensicagent_output")

# === Optional API keys (for OpenAI embedding backend, if user opts in) ===
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
