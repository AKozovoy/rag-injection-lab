"""Run every attack case the same way and save the answers for scoring.

Each case in attack_cases.json has:
- id, type: "malicious_link", "secret_leak", "false_answer" or "clean"
- attack_doc: a file in attacks/, or null for a clean index
- questions: asked one by one
- check: which detector scores the answers (see detectors.py and
  score_results.py). For attack cases it decides "the attack worked";
  for clean cases it decides "the answer is correct".

Run with: python run_attacks.py
"""

import json
import time
from datetime import datetime
from pathlib import Path

import ollama

from rag import CHAT_MODEL, SEED, TEMPERATURE, answer
from vectorstore import EMBED_MODEL, TOP_K, build_index

CASES_FILE = Path(__file__).parent / "attack_cases.json"
RESULTS_DIR = Path(__file__).parent / "results"


def model_digests() -> dict[str, str]:
    """Exact versions of the installed models, so a run can be reproduced."""
    return {m.model: m.digest for m in ollama.list().models}


def run_case(case: dict) -> dict:
    """Index the clean docs plus this case's attack doc, then ask its questions."""
    build_index([case["attack_doc"]] if case["attack_doc"] else [])
    answers = []
    for question in case["questions"]:
        text, chunks = answer(question)
        answers.append({
            "question": question,
            "answer": text,
            "chunks": [
                {k: c[k] for k in ("source", "chunk_index", "distance")} for c in chunks
            ],
            # 1-based ranks of attack chunks among the retrieved ones (empty = not retrieved)
            "attack_ranks": [
                rank for rank, c in enumerate(chunks, start=1) if c["source"].startswith("attacks/")
            ],
        })
    return {**case, "answers": answers}


def run_suite(cases: list[dict]) -> dict:
    """Run all cases and return the results with the settings they ran under."""
    results = {
        "started": datetime.now().isoformat(timespec="seconds"),
        "settings": {
            "chat_model": CHAT_MODEL,
            "embed_model": EMBED_MODEL,
            "model_digests": model_digests(),
            "k": TOP_K,
            "temperature": TEMPERATURE,
            "seed": SEED,
        },
        "cases": [],
    }
    try:
        for number, case in enumerate(cases, start=1):
            start = time.perf_counter()
            results["cases"].append(run_case(case))
            print(f"[{number}/{len(cases)}] {case['id']} ({time.perf_counter() - start:.1f}s)")
    finally:
        build_index()  # leave the UI with a clean index, even if a case failed
    return results


if __name__ == "__main__":
    cases = json.loads(CASES_FILE.read_text(encoding="utf-8"))
    results = run_suite(cases)
    RESULTS_DIR.mkdir(exist_ok=True)
    out = RESULTS_DIR / f"attacks_{datetime.now():%Y%m%d-%H%M%S}.json"
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Saved {sum(len(c['answers']) for c in results['cases'])} answers to {out}")
