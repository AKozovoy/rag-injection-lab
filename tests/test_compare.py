"""Comparison math, on hand-made runs (no model calls)."""

import copy

import pytest

import compare_defenses
from compare_defenses import (
    CONFIGS,
    build_rows,
    check_compatible,
    compare_outcomes,
    run_label,
    summarize,
)

LEAK = "SECRET_CODE=NW-7731-ALPHA"
SETTINGS = {"chat_model": "llama3.2", "embed_model": "nomic-embed-text",
            "model_digests": {"llama3.2:latest": "a80c"}, "k": 3, "temperature": 0, "seed": 42}


def test_compare_outcomes_matches_by_question():
    # The review's example: baseline wins A and B, the defense wins B and C.
    baseline = {("c", "A"): True, ("c", "B"): True, ("c", "C"): False}
    defense = {("c", "A"): False, ("c", "B"): True, ("c", "C"): True}
    assert compare_outcomes(baseline, defense) == {
        "baseline_wins": 2, "blocked": 1, "block_rate": 0.5, "new_wins": 1,
    }


def test_compare_outcomes_with_no_baseline_wins():
    result = compare_outcomes({("c", "A"): False}, {("c", "A"): True})
    assert result["block_rate"] is None and result["new_wins"] == 1


def test_run_label_matches_the_runner():
    assert run_label([]) == "none"
    assert run_label(CONFIGS["all"]) == "harden_sandwich+output_filter+scan+spotlight_datamark"


def _run(secret_answers, clean_answer="You have 30 days.", latency=1.0):
    """A tiny saved run: one secret case (questions A, B, C...) and one clean case."""
    return {"settings": copy.deepcopy(SETTINGS), "cases": [
        {"id": "secret_v1_direct", "type": "secret_leak", "check": {},
         "answers": [{"question": chr(65 + i), "answer": a, "latency_s": latency}
                     for i, a in enumerate(secret_answers)]},
        {"id": "clean_refund_window", "type": "clean", "check": {},
         "answers": [{"question": "q", "answer": clean_answer, "latency_s": latency}]},
    ]}


def test_summarize_counts_wins_clean_and_latency():
    s = summarize(_run([LEAK, "no leak"], latency=2.0))
    assert (s["secret_leak"]["wins"], s["secret_leak"]["tries"]) == (1, 2)
    assert s["clean"] == {"correct": 1, "total": 1, "false_alarms": 0}
    assert s["avg_latency_s"] == 2.0


def test_rows_show_blocked_and_new_wins(monkeypatch):
    monkeypatch.setattr(compare_defenses, "CONFIGS", {"none": [], "scan": ["scan"]})
    summaries = {
        "none": summarize(_run([LEAK, LEAK, "no leak"])),
        "scan": summarize(_run(["no leak", LEAK, LEAK])),
    }
    secret = {r["config"]: r for r in build_rows(summaries) if r["attack_type"] == "secret_leak"}
    # Same total (2 wins each), but one baseline win blocked and one new win.
    assert secret["scan"]["wins"] == 2
    assert (secret["scan"]["blocked"], secret["scan"]["new_wins"]) == (1, 1)
    assert secret["scan"]["block_rate"] == 0.5
    link = next(r for r in build_rows(summaries) if r["attack_type"] == "malicious_link")
    assert link["attack_success_rate"] is None and link["block_rate"] is None


def test_matching_runs_are_compatible():
    check_compatible({"none": _run([LEAK]), "scan": _run(["no leak"])})


@pytest.mark.parametrize("change", ["digest", "k", "questions"])
def test_mismatched_runs_are_refused(change):
    other = _run([LEAK])
    if change == "digest":
        other["settings"]["model_digests"] = {"llama3.2:latest": "ffff"}
    elif change == "k":
        other["settings"]["k"] = 5
    else:
        other["cases"][0]["answers"][0]["question"] = "a different question"
    with pytest.raises(ValueError):
        check_compatible({"none": _run([LEAK]), "scan": other})
