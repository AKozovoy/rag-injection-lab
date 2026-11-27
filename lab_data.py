"""Data for the Attack Lab page (#17): pure functions, no Streamlit, so they can be tested.

Everything is read from findings/ (committed), so the page works on a fresh clone.
Verdicts and attack doc texts come from the report itself, never from re-scoring
or the current attacks/ folder, so every view describes the same runs.
"""

import json
from pathlib import Path

import pandas as pd

from compare_defenses import ATTACK_TYPES, FINDINGS_DIR

REPORT_FILE = FINDINGS_DIR / "defense_comparison.json"
RUNS_DIR = FINDINGS_DIR / "runs"

# Readable names for the page; the data keeps its ids.
ATTACK_LABELS = {
    "malicious_link": "Malicious links",
    "secret_leak": "Secret leaks",
    "false_answer": "False answers",
}
DEFENSE_LABELS = {
    "spotlight": "spotlight",
    "spotlight_datamark": "spotlight + datamarking",
    "harden": "hardened prompt",
    "harden_sandwich": "hardened prompt + sandwich",
    "scan": "document scanner",
    "output_filter": "output filter",
}
# How the headline picks the best config (a product decision, shown on the page).
BEST_RULE = (
    "Best = among configs that kept every clean answer correct, the one with the "
    "fewest attacks getting through; ties go to the faster one."
)


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


def best_config(report: dict) -> str:
    """The best defended config by BEST_RULE (the baseline is never "best")."""
    stats = {}
    for r in report["rows"]:
        if r["config"] == "none":
            continue
        s = stats.setdefault(r["config"], {"wins": 0, "clean_ok": r["clean_correct"] == r["clean_total"],
                                           "latency": r["avg_latency_s"] or float("inf")})
        s["wins"] += r["wins"]
    candidates = {n: s for n, s in stats.items() if s["clean_ok"]} or stats  # fall back if none
    return min(candidates, key=lambda n: (candidates[n]["wins"], candidates[n]["latency"]))


def results_frame(report: dict) -> pd.DataFrame:
    """One row per config and attack type, in config order, with display labels."""
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


def headline(report: dict, best: str | None = None) -> list[dict]:
    """Baseline vs the best config, per attack type and for clean accuracy."""
    best = best or best_config(report)
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


def drilldown(report: dict, config: str, attack_type: str | None = None,
              case_id: str | None = None) -> list[dict]:
    """Every answer in one config's run with its saved verdict, optionally filtered."""
    verdicts = {(v["case"], v["question"]): v["verdict"] for v in report["verdicts"][config]}
    items = []
    for case in load_run(report, config)["cases"]:
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


def attack_doc_text(report: dict, name: str) -> str:
    """The attack doc's text as it was when the runs were made (saved in the report)."""
    return report["attack_docs"].get(name, f"({name}: no snapshot in this report)")
