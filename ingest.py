"""Load the Markdown docs and split them into chunks for embedding."""

from pathlib import Path

# Chunking settings: change these to try a different split.
DOCS_DIR = Path("docs")
SECTION_MARKER = "## "  # each line starting with this begins a new chunk


def load_docs(docs_dir: Path = DOCS_DIR) -> list[dict]:
    """Read every .md file in docs_dir and return its name and text."""
    return [
        {"source": path.name, "text": path.read_text(encoding="utf-8")}
        for path in sorted(docs_dir.glob("*.md"))
    ]


def chunk_doc(doc: dict) -> list[dict]:
    """Split one document into chunks, one per section heading."""
    lines = doc["text"].splitlines()

    # The "# Title" line names the whole document; we add it to every chunk
    # so a section like "## Eligibility" still says it's about refunds.
    title = lines[0].lstrip("# ").strip() if lines and lines[0].startswith("# ") else ""
    body = lines[1:] if title else lines

    # Group lines into sections: a new section starts at each SECTION_MARKER.
    sections: list[list[str]] = [[]]
    for line in body:
        if line.startswith(SECTION_MARKER):
            sections.append([])
        sections[-1].append(line)

    chunks = []
    for section in sections:
        text = "\n".join(section).strip()
        if not text:  # skip empty parts, e.g. nothing between title and first heading
            continue
        chunks.append({
            "text": f"{title}\n{text}" if title else text,
            "source": doc["source"],
            "chunk_index": len(chunks),
        })
    return chunks


def load_and_chunk(docs_dir: Path = DOCS_DIR) -> list[dict]:
    """Load all docs and return every chunk from all of them."""
    return [chunk for doc in load_docs(docs_dir) for chunk in chunk_doc(doc)]


if __name__ == "__main__":
    chunks = load_and_chunk()
    for chunk in chunks:
        print(f"--- {chunk['source']} #{chunk['chunk_index']} ({len(chunk['text'])} chars)")
        print(chunk["text"])
        print()
    print(f"Total: {len(chunks)} chunks")
