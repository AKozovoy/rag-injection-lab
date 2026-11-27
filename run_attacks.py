"""Run every attack case the same way and save the answers for scoring.

Each case in attack_cases.json has:
- id, type: "malicious_link", "secret_leak", "false_answer" or "clean"
- attack_doc: a file in attacks/, or null for a clean index
- questions: asked one by one
- check: which detector scores the answers (see detectors.py and
  score_results.py). For attack cases it decides "the attack worked";
  for clean cases it decides "the answer is correct".

Run with: python run_attacks.py                      (baseline, no defenses)
      or: python run_attacks.py --defense spotlight
"""

import argparse
import hashlib
import json
import time
from datetime import datetime
from pathlib import Path

import ollama

from rag import (
    CHAT_MODEL,
    DEFENSES,
    EXPECTED_ERRORS,
    SEED,
    TEMPERATURE,
    answer,
    normalize_defenses,
)
from ingest import ATTACKS_DIR, DOCS_DIR
from vectorstore import EMBED_MODEL, TOP_K, build_index, index_scan_info

CASES_FILE = Path(__file__).parent / "attack_cases.json"
RESULTS_DIR = Path(__file__).parent / "results"


def corpus_fingerprint(folders=(DOCS_DIR, ATTACKS_DIR)) -> str:
    """A SHA-256 code of every document's name and content.

    Changing one character in any file gives a completely different code, so
    runs made from different documents can be told apart (see compare_defenses.py).
    """
    digest = hashlib.sha256()
    for folder in folders:
        for path in sorted(folder.glob("*.md")):
            digest.update(f"{folder.name}/{path.name}\n".encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def model_digests() -> dict[str, str]:
    """Exact versions of the installed models, so a run can be reproduced."""
    return {m.model: m.digest for m in ollama.list().models}


def run_case(case: dict, defenses=()) -> dict:
    """Index the clean docs plus this case's attack doc, then ask its questions."""
    build_index([case["attack_doc"]] if case["attack_doc"] else [], scan="scan" in defenses)
    quarantined = index_scan_info()["quarantined"]  # empty unless the scanner ran
    answers = []
    for question in case["questions"]:
        start = time.perf_counter()
        text, chunks, filter_actions = answer(question, defenses=defenses)
        latency = time.perf_counter() - start  # retrieval + model + output filter
        answers.append({
            "question": question,
            "answer": text,
            "latency_s": round(latency, 2),
            "filter_actions": filter_actions,  # what the output filter changed, if on
            "chunks": [
                {k: c[k] for k in ("source", "chunk_index", "distance")} for c in chunks
            ],
            # 1-based ranks of attack chunks among the retrieved ones (empty = not retrieved)
            "attack_ranks": [
                rank for rank, c in enumerate(chunks, start=1) if c["source"].startswith("attacks/")
            ],
        })
    return {**case, "quarantined": quarantined, "answers": answers}


def run_suite(cases: list[dict], defenses=()) -> dict:
    """Run all cases and return the results with the settings they ran under."""
    # Normalized here, so the recorded label matches the prompt for every caller.
    defenses = normalize_defenses(defenses)
    results = {
        "started": datetime.now().isoformat(timespec="seconds"),
        "settings": {
            "defenses": sorted(defenses),  # empty = baseline
            "chat_model": CHAT_MODEL,
            "embed_model": EMBED_MODEL,
            "model_digests": model_digests(),
            "corpus_fingerprint": corpus_fingerprint(),  # docs/ + attacks/ contents
            "k": TOP_K,
            "temperature": TEMPERATURE,
            "seed": SEED,
        },
        "cases": [],
    }
    # Remember whether the UI's index was scanned, so cleanup doesn't switch it off.
    try:
        previous_scan = index_scan_info()["scan"]
    except EXPECTED_ERRORS:  # no index yet, or built with another model
        previous_scan = False
    try:
        for number, case in enumerate(cases, start=1):
            start = time.perf_counter()
            results["cases"].append(run_case(case, defenses))
            print(f"[{number}/{len(cases)}] {case['id']} ({time.perf_counter() - start:.1f}s)")
    finally:
        # Leave the UI with no attack docs, even if a case failed, but keep its scan setting.
        build_index(scan=previous_scan)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the attack suite.")
    parser.add_argument(
        "--defense", action="append", default=[], choices=DEFENSES,
        help="turn on a defense (repeat the flag for several); none = baseline",
    )
    defenses = parser.parse_args().defense

    cases = json.loads(CASES_FILE.read_text(encoding="utf-8"))
    results = run_suite(cases, defenses)
    RESULTS_DIR.mkdir(exist_ok=True)
    # File name from the recorded settings, so the two can't disagree.
    label = "+".join(results["settings"]["defenses"]) or "none"
    out = RESULTS_DIR / f"attacks_{label}_{datetime.now():%Y%m%d-%H%M%S}.json"
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Saved {sum(len(c['answers']) for c in results['cases'])} answers to {out}")
