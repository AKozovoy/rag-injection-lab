"""Comparison math, on hand-made runs (no model calls)."""

import copy

import pytest

import compare_defenses
from compare_defenses import (
    CONFIGS,
    build_rows,
    check_compatible,
    compare_outcomes,
    corpus_verified,
    run_label,
    summarize,
)

LEAK = "SECRET_CODE=NW-7731-ALPHA"
SETTINGS = {"chat_model": "llama3.2", "embed_model": "nomic-embed-text",
            "model_digests": {"llama3.2:latest": "a80c"}, "k": 3, "temperature": 0, "seed": 42,
            "corpus_fingerprint": "abc123"}


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
         "attack_doc": "secret_v1_direct.md",
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


def test_corpus_verified_needs_one_real_fingerprint():
    assert corpus_verified({"none": _run([LEAK]), "scan": _run([LEAK])})
    legacy = _run([LEAK])
    legacy["settings"].pop("corpus_fingerprint")
    assert not corpus_verified({"none": _run([LEAK]), "scan": legacy})  # one missing
    assert not corpus_verified({"none": legacy, "scan": copy.deepcopy(legacy)})  # all missing


def test_matching_runs_are_compatible():
    check_compatible({"none": _run([LEAK]), "scan": _run(["no leak"])})


def test_snapshots_refuse_runs_whose_documents_changed(monkeypatch):
    monkeypatch.setattr(compare_defenses, "corpus_fingerprint", lambda: "a-newer-fingerprint")
    with pytest.raises(ValueError):
        compare_defenses.attack_doc_snapshots({"none": _run([LEAK])})


def test_failed_publish_keeps_the_old_report_and_its_runs(monkeypatch, tmp_path):
    # An existing, consistent set of findings in a temp folder.
    monkeypatch.setattr(compare_defenses, "FINDINGS_DIR", tmp_path)
    (tmp_path / "runs").mkdir()
    (tmp_path / "runs" / "attacks_none_old.json").write_text("{}")
    (tmp_path / "defense_comparison.json").write_text('{"sources": {"none": "attacks_none_old.json"}}')

    new_run = tmp_path / "attacks_none_new.json"
    new_run.write_text("{}")
    def broken_copy(*args):
        raise OSError("disk full")
    monkeypatch.setattr(compare_defenses.shutil, "copy2", broken_copy)

    report = {"sources": {"none": "attacks_none_new.json"}, "rows": [{"config": "none"}]}
    with pytest.raises(OSError):
        compare_defenses.publish(report, {"none": new_run})

    # The old report still points at a run file that still exists.
    assert "attacks_none_old.json" in (tmp_path / "defense_comparison.json").read_text()
    assert (tmp_path / "runs" / "attacks_none_old.json").exists()


def test_failed_write_keeps_both_old_files(monkeypatch, tmp_path):
    monkeypatch.setattr(compare_defenses, "FINDINGS_DIR", tmp_path)
    (tmp_path / "defense_comparison.json").write_text("old json")
    (tmp_path / "defense_comparison.csv").write_text("old csv")
    new_run = tmp_path / "attacks_none_new.json"
    new_run.write_text("{}")

    real_write_temp = compare_defenses._write_temp
    def failing_write_temp(path, text):
        if path.suffix == ".json":  # the second file fails, after the CSV temp exists
            raise OSError("disk full")
        return real_write_temp(path, text)
    monkeypatch.setattr(compare_defenses, "_write_temp", failing_write_temp)

    report = {"sources": {"none": "attacks_none_new.json"}, "rows": [{"config": "none"}]}
    with pytest.raises(OSError):
        compare_defenses.publish(report, {"none": new_run})

    assert (tmp_path / "defense_comparison.json").read_text() == "old json"
    assert (tmp_path / "defense_comparison.csv").read_text() == "old csv"
    assert not list(tmp_path.glob("*.tmp"))  # temporary copies cleaned up


def test_publish_removes_unused_runs_only_after_writing(monkeypatch, tmp_path):
    monkeypatch.setattr(compare_defenses, "FINDINGS_DIR", tmp_path)
    (tmp_path / "runs").mkdir()
    (tmp_path / "runs" / "attacks_none_old.json").write_text("{}")
    new_run = tmp_path / "attacks_none_new.json"
    new_run.write_text("{}")

    report = {"sources": {"none": "attacks_none_new.json"}, "rows": [{"config": "none"}]}
    compare_defenses.publish(report, {"none": new_run})
    assert sorted(p.name for p in (tmp_path / "runs").iterdir()) == ["attacks_none_new.json"]
    assert "attacks_none_new.json" in (tmp_path / "defense_comparison.json").read_text()


@pytest.mark.parametrize("change", ["digest", "k", "questions", "attack_doc", "fingerprint"])
def test_mismatched_runs_are_refused(change):
    other = _run([LEAK])
    if change == "digest":
        other["settings"]["model_digests"] = {"llama3.2:latest": "ffff"}
    elif change == "k":
        other["settings"]["k"] = 5
    elif change == "questions":
        other["cases"][0]["answers"][0]["question"] = "a different question"
    elif change == "attack_doc":
        other["cases"][0]["attack_doc"] = "secret_v1_reworded.md"
    else:
        other["settings"]["corpus_fingerprint"] = "def456"  # same names, edited content
    with pytest.raises(ValueError):
        check_compatible({"none": _run([LEAK]), "scan": other})
