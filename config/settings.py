"""Global configuration for the RAG system.

All tunable parameters live here so individual modules stay declarative.
Environment variables (when set) take precedence over the defaults below,
which lets the same code run locally and in deployed environments.
"""

import os
from pathlib import Path

# === Project paths ===
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"

RAW_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# === Chunk settings ===
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "500"))
CHUNK_OVERLAP = int(os.getenv("CHUNK_OVERLAP", "50"))

# === Embedding settings ===
# Options: "sentence-transformers/all-MiniLM-L6-v2" (en, 384-d)
#          "jhgan/ko-sroberta-multitask"           (ko, 768-d)
#          "openai:text-embedding-3-small"         (api, 1536-d)
EMBEDDING_MODEL = os.getenv(
    "EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"
)
EMBEDDING_DIMENSION = int(os.getenv("EMBEDDING_DIMENSION", "384"))

# === Retrieval settings ===
SIMILARITY_THRESHOLD = float(os.getenv("SIMILARITY_THRESHOLD", "0.7"))
TOP_K = int(os.getenv("TOP_K", "5"))

# === VectorDB settings ===
VECTOR_DB_TYPE = os.getenv("VECTOR_DB_TYPE", "chromadb")  # "chromadb" | "milvus"
CHROMA_PERSIST_DIR = os.getenv(
    "CHROMA_PERSIST_DIR", str(DATA_DIR / "chroma_db")
)
CHROMA_COLLECTION = os.getenv("CHROMA_COLLECTION", "rag_documents")

# === LLM settings ===
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic")  # "anthropic" | "openai"
LLM_MODEL = os.getenv("LLM_MODEL", "claude-sonnet-4-20250514")
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "1024"))

# === Web search settings ===
WEB_SEARCH_PROVIDER = os.getenv("WEB_SEARCH_PROVIDER", "tavily")  # "tavily" | "serpapi"
WEB_SEARCH_TOP_K = int(os.getenv("WEB_SEARCH_TOP_K", "5"))

# === Logging DB ===
LOG_DB_URL = os.getenv("LOG_DB_URL", f"sqlite:///{DATA_DIR / 'logs.db'}")

# === API keys (read lazily by callers; leave blank for offline runs) ===
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")
SERPAPI_API_KEY = os.getenv("SERPAPI_API_KEY", "")

# === OCR settings ===
# pytesseract requires the tesseract binary on PATH (or set TESSERACT_CMD).
TESSERACT_CMD = os.getenv("TESSERACT_CMD", "")
OCR_LANGUAGES = os.getenv("OCR_LANGUAGES", "eng+kor")
