"""Embed chunks with Ollama, store them in Chroma, and retrieve the closest ones."""

import json
import sys
from pathlib import Path

import chromadb
import ollama

from ingest import load_and_chunk, load_attacks

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


def build_index(attacks: list[str] | None = None, scan: bool = False) -> int:
    """Rebuild the collection from docs/ plus any chosen attack docs.

    With scan=True (defense #14), chunks the scanner flags are quarantined:
    left out of the index, and logged in its metadata. Returns how many chunks it holds.
    """
    attacks = sorted(attacks or [])
    chunks = load_and_chunk() + load_attacks(attacks)
    quarantined = []
    if scan:
        # Imported here, not at the top: scanner -> detectors -> rag -> vectorstore
        # would be a circular import while this module is still loading.
        from scanner import scan_chunk

        kept = []
        for c in chunks:
            if reasons := scan_chunk(c["text"]):
                quarantined.append({"id": f"{c['source']}:{c['chunk_index']}", "reasons": reasons})
            else:
                kept.append(c)
        chunks = kept
    # Attack docs with at least one chunk actually going in (fully quarantined ones don't count).
    attacks_in_index = sorted(
        {c["source"].removeprefix("attacks/") for c in chunks if c["source"].startswith("attacks/")}
    )
    # Embed first: if Ollama fails here, the old index is still untouched.
    # If the scanner quarantined everything, there is nothing to embed.
    embeddings = embed([DOC_PREFIX + c["text"] for c in chunks]) if chunks else []
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))

    # Delete and rebuild: chunks from removed or edited docs can't linger.
    if COLLECTION_NAME in [c.name for c in client.list_collections()]:
        client.delete_collection(COLLECTION_NAME)
    collection = client.create_collection(
        COLLECTION_NAME,
        configuration={"hnsw": {"space": DISTANCE}},
        metadata={
            "embed_model": EMBED_MODEL,  # checked when reading, see get_collection()
            "attacks": ",".join(attacks),  # attack docs selected for this build
            "attacks_in_index": ",".join(attacks_in_index),  # see index_attacks()
            # Chroma metadata only holds simple values, so the list is stored as JSON text.
            "scan": scan,
            "quarantined": json.dumps(quarantined),  # see index_scan_info()
        },
    )

    if chunks:  # an empty collection still keeps its metadata (and the quarantine log)
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


def index_attacks() -> list[str]:
    """Attack docs with at least one chunk in the current index (empty list = clean).

    A selected attack doc that the scanner fully quarantined is not listed.
    """
    metadata = get_collection().metadata or {}
    # Indexes built before this field existed only have the selected list.
    saved = metadata.get("attacks_in_index", metadata.get("attacks", ""))
    return saved.split(",") if saved else []


def index_scan_info() -> dict:
    """Whether the scanner ran on the current index, and what it quarantined."""
    metadata = get_collection().metadata or {}
    return {
        "scan": bool(metadata.get("scan", False)),
        "quarantined": json.loads(metadata.get("quarantined", "[]")),
    }


def retrieve(question: str, k: int = TOP_K) -> list[dict]:
    """Return the k chunks closest in meaning to the question."""
    collection = get_collection()
    if collection.count() == 0:  # e.g. the scanner quarantined everything
        return []
    results = collection.query(
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
