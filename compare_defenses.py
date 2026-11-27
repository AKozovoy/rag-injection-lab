"""Compare the defenses (#16): run each config, score it, save one table.

For each config and attack type: attack success rate (wins / tries) and block
rate (share of the baseline's wins the defense stopped), plus clean accuracy,
false alarms and average answer latency.

Run with: python compare_defenses.py              (runs all configs, ~10 minutes)
      or: python compare_defenses.py --from-saved (newest saved run per config, no model calls)

Raw runs stay in results/ (not committed); the table goes to findings/ (committed).
"""

import argparse
import csv
import json
import re
from datetime import datetime
from pathlib import Path

from rag import normalize_defenses
from run_attacks import CASES_FILE, RESULTS_DIR, run_suite
from score_results import score_run

FINDINGS_DIR = Path(__file__).parent / "findings"

# Config name -> defenses. "all" uses the strongest variant of each defense;
# "practical" only uses defenses that cost no clean accuracy in earlier runs.
CONFIGS = {
    "none": [],
    "spotlight": ["spotlight"],
    "spotlight_datamark": ["spotlight_datamark"],
    "harden": ["harden"],
    "harden_sandwich": ["harden_sandwich"],
    "scan": ["scan"],
    "output_filter": ["output_filter"],
    "all": ["spotlight_datamark", "harden_sandwich", "scan", "output_filter"],
    "practical": ["spotlight", "scan", "output_filter"],
}
ATTACK_TYPES = ("malicious_link", "secret_leak", "false_answer")


def run_label(defenses) -> str:
    """The label run_attacks.py puts in the file name of a run."""
    return "+".join(normalize_defenses(defenses)) or "none"


def latest_saved_run(defenses) -> dict:
    """The newest saved run for these defenses (exact label match)."""
    pattern = re.compile(rf"attacks_{re.escape(run_label(defenses))}_\d{{8}}-\d{{6}}\.json")
    files = [p for p in RESULTS_DIR.glob("attacks_*.json") if pattern.fullmatch(p.name)]
    if not files:
        raise FileNotFoundError(f"no saved run for {run_label(defenses)}: run without --from-saved")
    return json.loads(max(files, key=lambda p: p.stat().st_mtime).read_text(encoding="utf-8"))


def block_rate(baseline_wins: int, wins: int) -> float | None:
    """Share of the baseline's wins this defense stopped.

    None when the baseline had no wins (nothing to block). Can be negative:
    the defense let through more than the baseline did.
    """
    if baseline_wins == 0:
        return None
    return round((baseline_wins - wins) / baseline_wins, 2)


def summarize(results: dict) -> dict:
    """Counts for one run: wins per attack type, clean results, average latency."""
    rows = [r for r in score_run(results) if not r.get("unscored")]
    summary = {}
    for attack_type in ATTACK_TYPES:
        hits = [r for r in rows if r["type"] == attack_type]
        summary[attack_type] = {"wins": sum(r["success"] for r in hits), "tries": len(hits)}
    clean = [r for r in rows if r["type"] == "clean"]
    summary["clean"] = {
        "correct": sum(r["correct"] for r in clean),
        "total": len(clean),
        "false_alarms": sum(r["false_alarm"] for r in clean),
    }
    latencies = [a["latency_s"] for c in results["cases"] for a in c["answers"] if "latency_s" in a]
    summary["avg_latency_s"] = round(sum(latencies) / len(latencies), 2) if latencies else None
    return summary


def build_rows(summaries: dict[str, dict]) -> list[dict]:
    """One row per config and attack type, with that config's clean results repeated."""
    baseline = summaries["none"]
    rows = []
    for name, s in summaries.items():
        for attack_type in ATTACK_TYPES:
            wins, tries = s[attack_type]["wins"], s[attack_type]["tries"]
            rows.append({
                "config": name,
                "defenses": "+".join(normalize_defenses(CONFIGS[name])) or "none",
                "attack_type": attack_type,
                "wins": wins,
                "tries": tries,
                "attack_success_rate": round(wins / tries, 2) if tries else None,
                "block_rate": block_rate(baseline[attack_type]["wins"], wins),
                "clean_correct": s["clean"]["correct"],
                "clean_total": s["clean"]["total"],
                "false_alarms": s["clean"]["false_alarms"],
                "avg_latency_s": s["avg_latency_s"],
            })
    return rows


def _cell(row: dict) -> str:
    block = "n/a" if row["block_rate"] is None else f"{row['block_rate']:.0%}"
    return f"{row['wins']}/{row['tries']} (blocked {block})"


def print_table(rows: list[dict]) -> None:
    print(f"{'config':20s}{'links':22s}{'secrets':22s}{'false answers':22s}{'clean':8s}{'latency':>8s}")
    for name in dict.fromkeys(r["config"] for r in rows):
        by_type = {r["attack_type"]: r for r in rows if r["config"] == name}
        first = by_type[ATTACK_TYPES[0]]
        latency = "-" if first["avg_latency_s"] is None else f"{first['avg_latency_s']:.2f}s"
        print(
            f"{name:20s}"
            + "".join(f"{_cell(by_type[t]):22s}" for t in ATTACK_TYPES)
            + f"{first['clean_correct']}/{first['clean_total']:<6}{latency:>8s}"
        )


def save(rows: list[dict], settings: dict) -> None:
    """findings/defense_comparison.json (for the Attack Lab page) and .csv (for GitHub)."""
    FINDINGS_DIR.mkdir(exist_ok=True)
    report = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "settings": {k: v for k, v in settings.items() if k != "defenses"},
        "configs": {name: list(normalize_defenses(d)) for name, d in CONFIGS.items()},
        "rows": rows,
    }
    (FINDINGS_DIR / "defense_comparison.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    with open(FINDINGS_DIR / "defense_comparison.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compare the defenses.")
    parser.add_argument("--from-saved", action="store_true", help="use saved runs, no model calls")
    from_saved = parser.parse_args().from_saved

    cases = json.loads(CASES_FILE.read_text(encoding="utf-8"))
    runs = {}
    for name, defenses in CONFIGS.items():
        if from_saved:
            runs[name] = latest_saved_run(defenses)
        else:
            print(f"\n=== {name} ===")
            runs[name] = run_suite(cases, defenses)
            RESULTS_DIR.mkdir(exist_ok=True)
            out = RESULTS_DIR / f"attacks_{run_label(defenses)}_{datetime.now():%Y%m%d-%H%M%S}.json"
            out.write_text(json.dumps(runs[name], indent=2, ensure_ascii=False), encoding="utf-8")

    rows = build_rows({name: summarize(run) for name, run in runs.items()})
    print()
    print_table(rows)
    save(rows, runs["none"]["settings"])
    print(f"\nSaved {FINDINGS_DIR / 'defense_comparison.json'} and .csv")
