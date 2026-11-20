"""
Chapter 17: Standalone Vector Search & RAG Pipeline Reference
Sentence-aware chunking, 384-dimensional normalized embeddings, and cosine similarity.
"""

import math
import hashlib
from typing import List, Dict, Any

VECTOR_DIMENSION = 384

def chunk_text(text: str, chunk_size: int = 400, overlap: int = 50) -> List[str]:
    """Splits document text into overlapping semantic windows without cutting sentences abruptly."""
    sentences = text.replace('\n', ' ').split('. ')
    chunks = []
    current_chunk = []
    current_len = 0

    for s in sentences:
        s_clean = s.strip()
        if not s_clean:
            continue
        s_with_dot = s_clean if s_clean.endswith('.') else s_clean + '.'
        current_chunk.append(s_with_dot)
        current_len += len(s_with_dot)

        if current_len >= chunk_size:
            chunks.append(' '.join(current_chunk))
            # Keep last sentence as overlap
            current_chunk = current_chunk[-1:] if overlap > 0 else []
            current_len = len(current_chunk[0]) if current_chunk else 0

    if current_chunk:
        chunks.append(' '.join(current_chunk))

    return chunks

def generate_embedding(text: str) -> List[float]:
    """Generates deterministic 384-dimensional L2-normalized embedding."""
    vec = [0.0] * VECTOR_DIMENSION
    words = text.lower().split()
    for w in words:
        h = int(hashlib.sha256(w.encode('utf-8')).hexdigest(), 16)
        idx = h % VECTOR_DIMENSION
        sign = 1.0 if (h >> 8) & 1 else -1.0
        vec[idx] += sign * (1.0 + (h % 10) / 10.0)

    # L2 normalize
    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 0:
        vec = [round(v / norm, 6) for v in vec]
    return vec

def cosine_similarity(v1: List[float], v2: List[float]) -> float:
    """Calculates cosine similarity between two normalized vectors."""
    return sum(a * b for a, b in zip(v1, v2))

if __name__ == "__main__":
    sample_text = (
        "Akira ransomware leverages compromised SonicWall and Cisco VPN endpoints for initial perimeter access. "
        "Upon execution, the binary establishes persistence using scheduled tasks and disables Volume Shadow Copies. "
        "Exfiltration is staged through mega.nz cloud storage before executing ChaCha20 encryption."
    )
    chunks = chunk_text(sample_text)
    print(f"Generated {len(chunks)} chunks.")
    emb = generate_embedding(chunks[0])
    print(f"Embedding dimension: {len(emb)}, L2 Norm: {math.sqrt(sum(x*x for x in emb)):.4f}")

