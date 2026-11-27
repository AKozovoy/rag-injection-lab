"""Attack Lab data and page, using the committed findings (no model calls)."""

import copy
from pathlib import Path

from streamlit.testing.v1 import AppTest

import score_results
from lab_data import (
    attack_doc_text,
    best_config,
    config_frame,
    defenses_label,
    drilldown,
    headline,
    load_report,
    results_frame,
)

REPORT = load_report()


def _row(config: str, attack_type: str) -> dict:
    return next(r for r in REPORT["rows"] if r["config"] == config and r["attack_type"] == attack_type)


def test_results_frame_has_one_row_per_config_and_attack_type():
    frame = results_frame(REPORT)
    assert len(frame) == len(REPORT["configs"]) * 3
    assert set(frame["attack"]) == {"Malicious links", "Secret leaks", "False answers"}
    assert all("/" in cell for cell in frame["cell"])


def test_defenses_label_is_readable_and_in_pipeline_order():
    assert defenses_label(["output_filter", "scan", "spotlight"]) == (
        "spotlight + document scanner + output filter"
    )
    assert defenses_label("output_filter+scan+spotlight") == (
        "spotlight + document scanner + output filter"
    )
    assert defenses_label([]) == defenses_label("none") == "no defense"


def test_config_frame_has_one_row_per_config():
    frame = config_frame(REPORT)
    assert list(frame["config"]) == list(REPORT["configs"])


def test_best_config_follows_the_rule():
    # Full clean accuracy first, then fewest total wins, then speed; never the baseline.
    report = {"rows": [
        {"config": "none", "wins": 0, "clean_correct": 5, "clean_total": 5, "avg_latency_s": 1.0},
        {"config": "a", "wins": 1, "clean_correct": 4, "clean_total": 5, "avg_latency_s": 1.0},
        {"config": "b", "wins": 3, "clean_correct": 5, "clean_total": 5, "avg_latency_s": 2.0},
        {"config": "c", "wins": 3, "clean_correct": 5, "clean_total": 5, "avg_latency_s": 1.5},
    ]}
    assert best_config(report) == "c"  # "a" has fewer wins but broke a clean answer


def test_headline_compares_baseline_with_best():
    tiles = {t["label"]: t for t in headline(REPORT)}
    best = best_config(REPORT)
    assert tiles["Secret leaks"]["baseline"] == _row("none", "secret_leak")["wins"]
    assert tiles["Secret leaks"]["best"] == _row(best, "secret_leak")["wins"]
    assert tiles["Clean answers correct"]["tries"] == 5


def test_drilldown_verdicts_match_the_table():
    items = drilldown(REPORT, "none", attack_type="secret_leak")
    wins = sum(i["verdict"].startswith("attack won") for i in items)
    row = _row("none", "secret_leak")
    assert len(items) == row["tries"] and wins == row["wins"]


def test_drilldown_uses_saved_verdicts_not_current_rules(monkeypatch):
    # Even if scoring changed (or broke), the drill-down shows what the report saved.
    monkeypatch.setattr(score_results, "score_run", lambda results: 1 / 0)
    items = drilldown(REPORT, "none", attack_type="secret_leak")
    assert sum(i["verdict"].startswith("attack won") for i in items) == _row("none", "secret_leak")["wins"]


def test_drilldown_filters_by_case():
    items = drilldown(REPORT, "none", case_id="secret_v3_roleplay")
    assert {i["case"] for i in items} == {"secret_v3_roleplay"}
    assert all(i["attack_doc"] == "secret_v3_roleplay.md" for i in items)


def test_attack_doc_text_comes_from_the_report_snapshot():
    assert "DiagBot" in attack_doc_text(REPORT, "secret_v3_roleplay.md")
    edited = copy.deepcopy(REPORT)
    edited["attack_docs"]["secret_v3_roleplay.md"] = "snapshot text"
    assert attack_doc_text(edited, "secret_v3_roleplay.md") == "snapshot text"  # not the file
    assert "no snapshot" in attack_doc_text(REPORT, "no_such_doc.md")


def test_page_loads_and_drills_down():
    page = Path(__file__).parent.parent / "pages" / "1_Attack_Lab.py"
    at = AppTest.from_file(str(page), default_timeout=60).run()
    assert not at.exception
    assert at.title[0].value == "Attack Lab"
    assert len(at.metric) == 4
    at.selectbox[0].set_value("none").run()
    at.selectbox[1].set_value("Secret leaks").run()
    at.checkbox[0].check().run()
    counts = [t.value for t in at.text if t.value.endswith(" answers")]
    assert counts == ["7 answers"]  # the baseline's 7 secret leaks
    assert not at.exception
