"""
RAG Configuration Module
Loads settings from environment variables and .env with production defaults.
"""

import os
from pathlib import Path
from dataclasses import dataclass, field

try:
    from dotenv import load_dotenv
    # Load .env from current directory or parent directory
    load_dotenv(override=False)
except ImportError:
    pass


@dataclass
class RAGConfig:
    """Centralized configuration for RAG & LLM subsystems."""

    # Base Paths
    BASE_DIR: Path = field(default_factory=lambda: Path(__file__).resolve().parent)
    DOCUMENTS_DIR: Path = field(default_factory=lambda: Path(__file__).resolve().parent / "documents")
    VECTOR_DB_DIR: Path = field(default_factory=lambda: Path(__file__).resolve().parent / "vector_store")
    CACHE_DIR: Path = field(default_factory=lambda: Path(__file__).resolve().parent / "cache")

    # Document Chunking Settings
    CHUNK_SIZE: int = int(os.getenv("RAG_CHUNK_SIZE", "500"))  # in words/tokens approx
    CHUNK_OVERLAP: int = int(os.getenv("RAG_CHUNK_OVERLAP", "80"))

    # Embedding Settings
    # Options: "auto", "tfidf", "sentence_transformers", "gemini", "openai"
    EMBEDDING_PROVIDER: str = os.getenv("RAG_EMBEDDING_PROVIDER", "tfidf")
    EMBEDDING_MODEL_NAME: str = os.getenv("RAG_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
    EMBEDDING_DIMENSION: int = int(os.getenv("RAG_EMBEDDING_DIMENSION", "1024"))

    # Vector Store & Retrieval Settings
    TOP_K: int = int(os.getenv("RAG_TOP_K", "4"))
    # Conservative floor: TF-IDF OOD queries (e.g. recipes) top out ~0.21–0.25,
    # while typical in-domain cyber queries score ~0.27+. Override via RAG_SIMILARITY_THRESHOLD.
    SIMILARITY_THRESHOLD: float = float(os.getenv("RAG_SIMILARITY_THRESHOLD", "0.26"))
    MAX_CONTEXT_LENGTH: int = int(os.getenv("RAG_MAX_CONTEXT_LENGTH", "3000"))

    # LLM Settings
    # Options: "auto", "gemini", "openai", "ollama", "offline_soc"
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "gemini")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3")

    # Temperature and Generation
    TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.2"))
    MAX_TOKENS: int = int(os.getenv("LLM_MAX_TOKENS", "1200"))

    # Hard wall-clock cap (seconds) on each live LLM call. When the provider is
    # slow or unreachable, the call gives up after this and falls through to the
    # fast local knowledge-base answer.
    LLM_TIMEOUT: float = float(os.getenv("LLM_TIMEOUT", "3"))

    def __post_init__(self):
        """Ensure runtime directories exist."""
        self.DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)
        self.VECTOR_DB_DIR.mkdir(parents=True, exist_ok=True)
        self.CACHE_DIR.mkdir(parents=True, exist_ok=True)


# Global default configuration instance
default_config = RAGConfig()
