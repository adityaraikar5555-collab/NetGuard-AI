"""
Document Chunking Module
Provides markdown-aware recursive chunking with rich metadata preservation and deduplication hashing.
"""

import re
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class DocumentChunk:
    """Represents a single chunk of text with complete provenance metadata."""
    chunk_id: str
    text: str
    document_name: str
    source_path: str
    category: str
    attack_type: Optional[str] = None
    section_title: str = "General"
    chunk_index: int = 0
    token_count: int = 0
    content_hash: str = ""
    extra_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DocumentChunk":
        return cls(**data)


class DocumentChunker:
    """Intelligent Markdown and Text chunker with semantic boundaries and overlap."""

    def __init__(self, chunk_size: int = 500, chunk_overlap: int = 80):
        self.chunk_size = max(50, chunk_size)
        self.chunk_overlap = max(0, min(chunk_overlap, self.chunk_size // 2))

    def clean_text(self, text: str) -> str:
        """Sanitizes text, normalizes line endings and removes redundant blank lines."""
        if not text:
            return ""
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        # Normalize multiple empty lines to at most two
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    def infer_category_and_attack(self, file_path: Path, text: str) -> (str, Optional[str]):
        """Infers category and primary attack type from path structure and contents."""
        path_str = str(file_path).lower()

        # Category detection from directory or file name
        if "network_security" in path_str:
            category = "Network Security"
        elif "datasets_and_ml" in path_str:
            category = "Datasets & Machine Learning"
        elif "soc_procedures" in path_str:
            category = "SOC Procedures"
        elif "mitigation" in path_str:
            category = "Mitigation & Hardening"
        else:
            category = "General Cybersecurity"

        # Attack type detection. Benchmark documents are checked first so a
        # filename such as cicids2017_guide.md is not accidentally labeled DoS
        # merely because its contents mention DoS attacks.
        attack_type = None
        if "cicids" in path_str:
            attack_type = "CICIDS-2017 Benchmark"
        elif "nsl_kdd" in path_str:
            attack_type = "NSL-KDD Benchmark"
        elif "reconnaissance" in path_str or "port_scan" in path_str or "port scan" in text.lower():
            attack_type = "Port Scanning / Probe"
        elif "brute_force" in path_str or "patator" in text.lower():
            attack_type = "Brute Force"
        elif "botnet" in path_str or "c2" in path_str or "beacon" in text.lower():
            attack_type = "Botnet / C2"
        elif "web" in path_str or "sqli" in text.lower() or "xss" in text.lower():
            attack_type = "Web Attack"
        elif "infiltration" in path_str or "lateral" in text.lower():
            attack_type = "Infiltration / Lateral Movement"
        elif "ddos" in path_str or "dos" in path_str or "syn flood" in text.lower() or "udp flood" in text.lower():
            attack_type = "DoS/DDoS"

        return category, attack_type

    def chunk_document(self, file_path: Path, content: Optional[str] = None) -> List[DocumentChunk]:
        """Chunks a single file by headers and paragraphs, maintaining context overlap."""
        if content is None:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

        content = self.clean_text(content)
        if not content:
            return []

        doc_name = file_path.name
        source_path = str(file_path.as_posix())
        category, attack_type = self.infer_category_and_attack(file_path, content)

        # Split content into sections based on Markdown headers (# and ##)
        section_pattern = re.compile(r"(^#{1,3}\s+.+$)", re.MULTILINE)
        splits = section_pattern.split(content)

        sections = []
        current_header = "Introduction"

        if splits:
            i = 0
            while i < len(splits):
                segment = splits[i].strip()
                if not segment:
                    i += 1
                    continue
                if section_pattern.match(splits[i]):
                    current_header = splits[i].lstrip("#").strip()
                    if i + 1 < len(splits):
                        section_text = splits[i + 1].strip()
                        sections.append((current_header, section_text))
                        i += 2
                    else:
                        sections.append((current_header, ""))
                        i += 1
                else:
                    sections.append((current_header, segment))
                    i += 1
        else:
            sections = [("General", content)]

        chunks: List[DocumentChunk] = []
        chunk_idx = 0

        for header, section_text in sections:
            if not section_text:
                continue

            words = section_text.split()
            if not words:
                continue

            if len(words) <= self.chunk_size:
                chunk_text = f"## {header}\n\n{section_text}" if header != "General" else section_text
                chunk_id = self._generate_chunk_id(doc_name, chunk_idx, chunk_text)
                chunks.append(
                    DocumentChunk(
                        chunk_id=chunk_id,
                        text=chunk_text,
                        document_name=doc_name,
                        source_path=source_path,
                        category=category,
                        attack_type=attack_type,
                        section_title=header,
                        chunk_index=chunk_idx,
                        token_count=len(words),
                        content_hash=hashlib.sha256(chunk_text.encode("utf-8")).hexdigest(),
                    )
                )
                chunk_idx += 1
            else:
                # Sliding window with overlap
                start = 0
                step = self.chunk_size - self.chunk_overlap
                while start < len(words):
                    end = min(start + self.chunk_size, len(words))
                    window_words = words[start:end]
                    sub_text = " ".join(window_words)
                    full_chunk_text = f"## {header} (Part)\n\n{sub_text}" if header != "General" else sub_text

                    chunk_id = self._generate_chunk_id(doc_name, chunk_idx, full_chunk_text)
                    chunks.append(
                        DocumentChunk(
                            chunk_id=chunk_id,
                            text=full_chunk_text,
                            document_name=doc_name,
                            source_path=source_path,
                            category=category,
                            attack_type=attack_type,
                            section_title=header,
                            chunk_index=chunk_idx,
                            token_count=len(window_words),
                            content_hash=hashlib.sha256(full_chunk_text.encode("utf-8")).hexdigest(),
                        )
                    )
                    chunk_idx += 1
                    if end >= len(words):
                        break
                    start += step

        return chunks

    def _generate_chunk_id(self, doc_name: str, index: int, text: str) -> str:
        """Generates a stable deterministic ID for a chunk."""
        clean_name = re.sub(r"[^a-zA-Z0-9_-]", "_", doc_name.replace(".md", "").replace(".txt", ""))
        short_hash = hashlib.md5(text.encode("utf-8")).hexdigest()[:8]
        return f"{clean_name}_c{index:03d}_{short_hash}"
