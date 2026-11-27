"""Embed chunks with Ollama and store them in a persistent Chroma collection."""

from pathlib import Path

import chromadb
import ollama

from ingest import load_and_chunk

# Vector store settings: change these to try a different setup.
CHROMA_DIR = Path(__file__).parent / "chroma_db"
COLLECTION_NAME = "northwind_docs"
EMBED_MODEL = "nomic-embed-text"
# nomic-embed-text was trained with these task prefixes; they improve retrieval.
DOC_PREFIX = "search_document: "
QUERY_PREFIX = "search_query: "  # used for questions in #3
DISTANCE = "cosine"  # compare vector directions, not lengths


def embed(texts: list[str]) -> list[list[float]]:
    """Turn each text into a vector with the Ollama embedding model."""
    response = ollama.embed(model=EMBED_MODEL, input=texts)
    return [list(vector) for vector in response.embeddings]


def build_index() -> int:
    """Rebuild the collection from docs/ and return how many chunks it holds."""
    chunks = load_and_chunk()
    # Embed first: if Ollama fails here, the old index is still untouched.
    embeddings = embed([DOC_PREFIX + c["text"] for c in chunks])
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))

    # Delete and rebuild: chunks from removed or edited docs can't linger.
    if COLLECTION_NAME in [c.name for c in client.list_collections()]:
        client.delete_collection(COLLECTION_NAME)
    collection = client.create_collection(
        COLLECTION_NAME,
        configuration={"hnsw": {"space": DISTANCE}},
    )

    collection.add(
        ids=[f"{c['source']}:{c['chunk_index']}" for c in chunks],
        documents=[c["text"] for c in chunks],
        embeddings=embeddings,
        metadatas=[{"source": c["source"], "chunk_index": c["chunk_index"]} for c in chunks],
    )
    return collection.count()


if __name__ == "__main__":
    print(f"Indexed {build_index()} chunks into {CHROMA_DIR}")
