"""Data for the Attack Lab page (#17): pure functions, no Streamlit, so they can be tested.

Everything is read from findings/ (committed), so the page works on a fresh clone.
"""

import json
from pathlib import Path

import pandas as pd

from compare_defenses import ATTACK_TYPES, FINDINGS_DIR
from ingest import ATTACKS_DIR
from score_results import score_run

REPORT_FILE = FINDINGS_DIR / "defense_comparison.json"
RUNS_DIR = FINDINGS_DIR / "runs"

# Readable names for the page; the data keeps its ids.
ATTACK_LABELS = {
    "malicious_link": "Malicious links",
    "secret_leak": "Secret leaks",
    "false_answer": "False answers",
}
BEST_CONFIG = "practical"  # the config the headline compares with the baseline
DEFENSE_LABELS = {
    "spotlight": "spotlight",
    "spotlight_datamark": "spotlight + datamarking",
    "harden": "hardened prompt",
    "harden_sandwich": "hardened prompt + sandwich",
    "scan": "document scanner",
    "output_filter": "output filter",
}


def defenses_label(defenses) -> str:
    """Readable defense names in pipeline order: prompt, then index, then answer."""
    if isinstance(defenses, str):  # the "a+b" form saved in the report rows
        defenses = [] if defenses == "none" else defenses.split("+")
    ordered = [d for d in DEFENSE_LABELS if d in defenses]
    return " + ".join(DEFENSE_LABELS[d] for d in ordered) or "no defense"


def load_report(path: Path = REPORT_FILE) -> dict:
    """The comparison saved by compare_defenses.py."""
    return json.loads(path.read_text(encoding="utf-8"))


def load_run(report: dict, config: str, runs_dir: Path = RUNS_DIR) -> dict:
    """The saved run behind one config's numbers."""
    return json.loads((runs_dir / report["sources"][config]).read_text(encoding="utf-8"))


def results_frame(report: dict) -> pd.DataFrame:
    """One row per config and attack type, in config order, with a display label."""
    frame = pd.DataFrame(report["rows"])
    frame["attack"] = frame["attack_type"].map(ATTACK_LABELS)
    frame["defenses"] = frame["defenses"].map(defenses_label)
    frame["cell"] = frame["wins"].astype(str) + "/" + frame["tries"].astype(str)
    frame["blocked_text"] = [
        "n/a" if base == 0 else f"{blocked}/{base}"
        for blocked, base in zip(frame["blocked"], frame["baseline_wins"])
    ]
    return frame


def config_frame(report: dict) -> pd.DataFrame:
    """One row per config: its defenses, clean accuracy, false alarms, latency."""
    frame = pd.DataFrame(report["rows"]).drop_duplicates("config")
    frame["clean"] = frame["clean_correct"].astype(str) + "/" + frame["clean_total"].astype(str)
    frame["defenses"] = frame["defenses"].map(defenses_label)
    return frame[["config", "defenses", "clean", "false_alarms", "avg_latency_s"]].reset_index(
        drop=True
    )


def headline(report: dict, best: str = BEST_CONFIG) -> list[dict]:
    """Baseline vs the best config, per attack type and for clean accuracy."""
    rows = {(r["config"], r["attack_type"]): r for r in report["rows"]}
    tiles = [
        {
            "label": ATTACK_LABELS[t],
            "baseline": rows[("none", t)]["wins"],
            "best": rows[(best, t)]["wins"],
            "tries": rows[(best, t)]["tries"],
        }
        for t in ATTACK_TYPES
    ]
    clean = rows[(best, ATTACK_TYPES[0])]
    base_clean = rows[("none", ATTACK_TYPES[0])]
    tiles.append({
        "label": "Clean answers correct",
        "baseline": base_clean["clean_correct"],
        "best": clean["clean_correct"],
        "tries": clean["clean_total"],
    })
    return tiles


def _verdict(row: dict) -> str:
    """A short, readable verdict for one scored answer."""
    if row.get("unscored"):
        return "unscored"
    if row["type"] == "clean":
        return "correct" if row["correct"] else "wrong"
    if "outcome" in row:  # false answers: attack / mixed / correct / neither
        return {"attack": "attack won", "mixed": "attack won (mixed)"}.get(
            row["outcome"], row["outcome"]
        )
    return "attack won" if row["success"] else "blocked"


def drilldown(run: dict, attack_type: str | None = None, case_id: str | None = None) -> list[dict]:
    """Every answer in a run with its verdict, optionally for one attack type or case."""
    verdicts = {
        (r["case"], r.get("question")): _verdict(r) for r in score_run(run) if not r.get("unscored")
    }
    items = []
    for case in run["cases"]:
        if attack_type and case["type"] != attack_type:
            continue
        if case_id and case["id"] != case_id:
            continue
        for a in case["answers"]:
            items.append({
                "case": case["id"],
                "type": case["type"],
                "attack_doc": case.get("attack_doc"),
                "question": a["question"],
                "answer": a["answer"],
                "verdict": verdicts.get((case["id"], a["question"]), "unscored"),
                "attack_ranks": a.get("attack_ranks", []),
                "filter_actions": a.get("filter_actions", []),
                "quarantined": [q["id"] for q in case.get("quarantined", [])],
            })
    return items


def attack_doc_text(name: str, attacks_dir: Path = ATTACKS_DIR) -> str:
    """The attack document's text, or a note if it's gone."""
    path = attacks_dir / name
    return path.read_text(encoding="utf-8") if path.is_file() else f"({name} not found)"
