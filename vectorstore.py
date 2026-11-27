"""Embed chunks with Ollama, store them in Chroma, and retrieve the closest ones."""

import sys
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
TOP_K = 3  # how many chunks to retrieve per question


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
        metadata={"embed_model": EMBED_MODEL},  # checked when reading, see get_collection()
    )

    collection.add(
        ids=[f"{c['source']}:{c['chunk_index']}" for c in chunks],
        documents=[c["text"] for c in chunks],
        embeddings=embeddings,
        metadatas=[{"source": c["source"], "chunk_index": c["chunk_index"]} for c in chunks],
    )
    return collection.count()


def get_collection() -> chromadb.Collection:
    """Open the existing collection, or fail with a clear message."""
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    if COLLECTION_NAME not in [c.name for c in client.list_collections()]:
        raise RuntimeError("Index not found: run `python vectorstore.py` first")
    collection = client.get_collection(COLLECTION_NAME)

    # Vectors from different models can't be compared, so refuse a mismatch.
    built_with = (collection.metadata or {}).get("embed_model")
    if built_with != EMBED_MODEL:
        raise RuntimeError(
            f"Index was built with {built_with} but EMBED_MODEL is {EMBED_MODEL}: "
            "run `python vectorstore.py` to rebuild"
        )
    return collection


def retrieve(question: str, k: int = TOP_K) -> list[dict]:
    """Return the k chunks closest in meaning to the question."""
    results = get_collection().query(
        query_embeddings=embed([QUERY_PREFIX + question]),
        n_results=k,
    )
    # Chroma returns one list per query; we sent one question, so take [0].
    return [
        {
            "text": text,
            "source": meta["source"],
            "chunk_index": meta["chunk_index"],
            "distance": distance,
        }
        for text, meta, distance in zip(
            results["documents"][0], results["metadatas"][0], results["distances"][0]
        )
    ]


if __name__ == "__main__":
    if len(sys.argv) > 1:  # a question was given: search the index
        question = " ".join(sys.argv[1:])
        for chunk in retrieve(question):
            print(f"--- {chunk['source']} #{chunk['chunk_index']} (distance {chunk['distance']:.3f})")
            print(chunk["text"])
            print()
    else:  # no question: rebuild the index
        print(f"Indexed {build_index()} chunks into {CHROMA_DIR}")
