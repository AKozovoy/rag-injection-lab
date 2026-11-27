"""Attack Lab data and page, using the committed findings (no model calls)."""

from pathlib import Path

from streamlit.testing.v1 import AppTest

from lab_data import (
    attack_doc_text,
    config_frame,
    defenses_label,
    drilldown,
    headline,
    load_report,
    load_run,
    results_frame,
)

REPORT = load_report()


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


def test_headline_compares_baseline_with_best():
    tiles = {t["label"]: t for t in headline(REPORT)}
    # Matches the rows in the report, whatever the current numbers are.
    rows = {(r["config"], r["attack_type"]): r for r in REPORT["rows"]}
    assert tiles["Secret leaks"]["baseline"] == rows[("none", "secret_leak")]["wins"]
    assert tiles["Secret leaks"]["best"] == rows[("practical", "secret_leak")]["wins"]
    assert tiles["Clean answers correct"]["tries"] == 5


def test_drilldown_verdicts_match_the_table():
    run = load_run(REPORT, "none")
    items = drilldown(run, attack_type="secret_leak")
    wins = sum(i["verdict"].startswith("attack won") for i in items)
    row = next(r for r in REPORT["rows"] if r["config"] == "none" and r["attack_type"] == "secret_leak")
    assert len(items) == row["tries"] and wins == row["wins"]


def test_drilldown_filters_by_case():
    items = drilldown(load_run(REPORT, "none"), case_id="secret_v3_roleplay")
    assert {i["case"] for i in items} == {"secret_v3_roleplay"}
    assert all(i["attack_doc"] == "secret_v3_roleplay.md" for i in items)


def test_attack_doc_text_reads_the_file_or_says_missing():
    assert "DiagBot" in attack_doc_text("secret_v3_roleplay.md")
    assert "not found" in attack_doc_text("no_such_doc.md")


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
