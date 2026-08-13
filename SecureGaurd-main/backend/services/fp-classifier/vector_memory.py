"""
vector_memory.py — Vector Memory (Semantic Similarity Lookup)

Qdrant (either Docker-based or local in-memory fallback) aur sentence-transformers
ko use karke, real developer feedback se similarity matches dhondta hai.
Retraining cycle ke bina hi recent feedback se seekhne ke liye strong priors compute karta hai.
"""

import os
import uuid
import time
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(os.path.dirname(BASE_DIR))

# ─── Load Environment Configuration ───────────────────────────────────────────
def load_env(path):
    env = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    parts = line.split("=", 1)
                    k = parts[0].strip()
                    v = parts[1].strip().strip("'").strip('"')
                    env[k] = v
    return env

env = load_env(os.path.join(BACKEND_DIR, ".env"))

# Configurable settings
QDRANT_URL = env.get("QDRANT_URL", "http://localhost:6333")
SIMILARITY_THRESHOLD = 0.85
COLLECTION_NAME = "finding_memory"

_client = None
_embedding_model = None


def get_embedding_model():
    """Lazily load SentenceTransformer model."""
    global _embedding_model
    if _embedding_model is None:
        print("[VectorMemory] Loading embedding model (all-MiniLM-L6-v2)...")
        from sentence_transformers import SentenceTransformer
        # HuggingFace will automatically cache the downloaded model files
        _embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        print("[VectorMemory] Embedding model loaded successfully.")
    return _embedding_model


def get_qdrant_client():
    """Lazily initialize and test QdrantClient connection, falling back to :memory: on failure."""
    global _client
    if _client is None:
        if QDRANT_URL:
            try:
                # Attempt connecting to external Qdrant instance
                client = QdrantClient(url=QDRANT_URL, timeout=3.0)
                client.get_collections()  # Simple heartbeat call
                _client = client
                print(f"[VectorMemory] Connected to Qdrant at {QDRANT_URL}")
            except Exception as e:
                print(f"[VectorMemory WARNING] Could not connect to Qdrant at {QDRANT_URL}: {e}")
                print("[VectorMemory] Falling back to local in-memory Qdrant store.")
                _client = QdrantClient(":memory:")
        else:
            print("[VectorMemory] No QDRANT_URL set, using local in-memory Qdrant store.")
            _client = QdrantClient(":memory:")

        # Initialize the collection
        try:
            if not _client.collection_exists(COLLECTION_NAME):
                _client.create_collection(
                    collection_name=COLLECTION_NAME,
                    vectors_config=VectorParams(size=384, distance=Distance.COSINE),
                )
                print(f"[VectorMemory] Created collection '{COLLECTION_NAME}' (384-dim, Cosine).")
        except Exception as e:
            print(f"[VectorMemory ERROR] Failed to initialize collection: {e}")

    return _client


def embed_text(text: str) -> list[float]:
    """Generates a 384-dimensional embedding vector for the given text."""
    if not text:
        return [0.0] * 384
    model = get_embedding_model()
    # Ensure it's a 1D list of floats
    embedding = model.encode(text).tolist()
    return embedding


def add_feedback(code_snippet: str, outcome: str, cwe_id: str, repo_id: str = None) -> bool:
    """
    Developer outcome feedback ko vector memory collection me save karta hai.
    
    Args:
        code_snippet (str): The code context of the finding.
        outcome (str): "REAL" or "FALSE_POSITIVE"
        cwe_id (str): CWE ID (e.g. CWE-89)
        repo_id (str): Optional repo identifier
    """
    if not code_snippet:
        return False
        
    try:
        client = get_qdrant_client()
        vector = embed_text(code_snippet)
        
        point_id = str(uuid.uuid4())
        payload = {
            "outcome": outcome,
            "cwe_id": cwe_id,
            "timestamp": int(time.time()),
            "repo_id": repo_id
        }
        
        client.upsert(
            collection_name=COLLECTION_NAME,
            points=[
                PointStruct(
                    id=point_id,
                    vector=vector,
                    payload=payload
                )
            ]
        )
        print(f"[VectorMemory] Successfully added feedback point: {outcome} for {cwe_id}")
        return True
    except Exception as e:
        print(f"[VectorMemory ERROR] add_feedback failed: {e}")
        return False


def lookup_similarity(code_snippet: str, cwe_id: str = None) -> dict:
    """
    Code snippet ke vectors compare karke similarity match lookup karta hai.
    
    Returns:
        dict: {"found": bool, "similarity": float, "past_outcome": "REAL" | "FALSE_POSITIVE"}
    """
    if not code_snippet:
        return {"found": False}
        
    try:
        client = get_qdrant_client()
        vector = embed_text(code_snippet)
        
        # Look up nearest neighbors (top 5 cosine matches)
        results = client.search(
            collection_name=COLLECTION_NAME,
            query_vector=vector,
            limit=5
        )
        
        if not results:
            return {"found": False}
            
        top_match = results[0]
        similarity = float(top_match.score)
        
        # Verify similarity exceeds the threshold
        if similarity >= SIMILARITY_THRESHOLD:
            past_outcome = top_match.payload.get("outcome")
            return {
                "found": True,
                "similarity": round(similarity, 4),
                "past_outcome": past_outcome
            }
            
    except Exception as e:
        print(f"[VectorMemory ERROR] similarity lookup failed: {e}")
        
    return {"found": False}
