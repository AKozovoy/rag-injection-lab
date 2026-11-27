"""Defense #14: scan chunks for injected instructions before they are indexed.

Flagged chunks are quarantined (left out of the index and logged). The rules
are heuristics: they catch instruction-style attacks, links and hidden text,
but no text pattern can tell a plain false fact from a true one.

Run with: python scanner.py   (report on every clean and attack chunk, no model needed)
"""

import re

from detectors import find_disallowed_domains
from ingest import list_attacks, load_and_chunk, load_attacks

# Rule name -> pattern. Generic words like "must" are left out on purpose:
# the real docs say "Items must be unused" and "Visitors must sign in".
SCAN_RULES = {
    "ai_instruction": re.compile(
        r"\b(?:ignore|disregard|forget)\b[^.\n]{0,40}\b(?:previous|prior|above|other|all|any)\b"
        r"[^.\n]{0,30}\b(?:instructions?|documents?|rules?)\b"
        r"|\bnote (?:to|for) the (?:ai|assistant)\b"
        r"|\b(?:you are now|act as|pretend to be)\b"
        r"|\boverrides? (?:all )?(?:previous|prior)\b"
        r"|\bdo not (?:mention|reveal) this\b"
        r"|\bassistant\s*:",
        re.IGNORECASE,
    ),
    "fake_system": re.compile(
        r"^\s*system\s*:|\[\s*end of context\s*\]|\bsystem (?:instruction|message)\b",
        re.IGNORECASE | re.MULTILINE,
    ),
    "secret_seeking": re.compile(
        r"secret[_ ]code|system prompt|internal configuration", re.IGNORECASE
    ),
    # HTML comments and zero-width characters: invisible to a human reader.
    "hidden_text": re.compile(r"<!--|[​-‏⁠﻿]"),
}


def scan_chunk(text: str) -> list[str]:
    """Names of the rules this chunk breaks (empty list = clean)."""
    reasons = [name for name, pattern in SCAN_RULES.items() if pattern.search(text)]
    if find_disallowed_domains(text):  # same check as the link detector (#11)
        reasons.append("external_link")
    return reasons


def print_report() -> None:
    """Which attack chunks get caught, and any false alarms on the clean docs."""
    clean = load_and_chunk()
    flagged_clean = [(c, scan_chunk(c["text"])) for c in clean if scan_chunk(c["text"])]
    print(f"Clean docs: {len(flagged_clean)}/{len(clean)} chunks flagged (false positives)")
    for chunk, reasons in flagged_clean:
        print(f"  {chunk['source']} #{chunk['chunk_index']}: {', '.join(reasons)}")

    print("\nAttack docs (chunks quarantined / total):")
    for name in list_attacks():
        chunks = load_attacks([name])
        results = [scan_chunk(c["text"]) for c in chunks]
        caught = sum(bool(r) for r in results)
        reasons = sorted({reason for r in results for reason in r})
        print(f"  {name:34s} {caught}/{len(chunks)}  {', '.join(reasons) or '-- not caught --'}")


if __name__ == "__main__":
    print_report()
