# CLAUDE.md

## Project: rag-injection-lab

A local "chat with your docs" (RAG) app used as a target for **indirect prompt injection**: malicious instructions hidden inside documents that the retriever feeds to the LLM. The goal is to build the app, attack it, add defenses, and **measure how many attacks each defense blocks**.

This is a learning project. The user wants to build the app code **step by step and understand it** — explain what you're doing, prefer small incremental changes, and don't write large chunks of app code unprompted.

## Stack (all local)

- **Python** 3.14, virtualenv in `.venv/` (`source .venv/bin/activate`)
- **Ollama** — `llama3.2` (chat) and `nomic-embed-text` (embeddings)
- **Chroma** — vector store, persisted to `chroma_db/` (gitignored, rebuildable from `docs/`)
- **Streamlit** — UI

Install deps: `pip install -r requirements.txt`

## Layout

- `docs/` — sample knowledge base for the fictional company **Northwind Gadgets** (refund policy, IT help guide, office rules, expense policy). Attack documents will be added later.
- `chroma_db/` — local vector DB (not committed)

## Attack goals

1. **Malicious links** — get the model to include an attacker-controlled URL in its answer.
2. **Secret leakage** — get the model to reveal a secret placed in the system prompt.
3. **False answers** — get the model to state wrong facts (e.g. a fake refund window).

## Plan

- **Week 1** — Basic RAG in the terminal: load/chunk docs, embed with nomic-embed-text, store in Chroma, retrieve, answer with llama3.2.
- **Week 2** — Streamlit chat UI; craft the first injection documents by hand and try them.
- **Week 3** — Automated attack suite (attack cases + success detectors) and defenses (e.g. delimiting/spotlighting retrieved text, instruction hierarchy in the system prompt, input/output filtering, link allowlisting, secret canary detection). Measure block rate per defense.
- **Week 4** — "Attack Lab" results page in Streamlit and a README presenting the findings.

## Notes

- Attacks target only this local lab app and fictional data.
- Keep the attack suite deterministic where possible (fixed seeds/temperature 0) so defense comparisons are fair.
