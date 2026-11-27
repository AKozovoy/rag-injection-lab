"""Compare the defenses (#16): run each config, score it, save one table.

For each config and attack type: attack success rate (wins / tries), and,
matched question by question against the baseline, how many baseline wins the
defense blocked and how many new wins it let through. Plus clean accuracy,
false alarms and average answer latency.

Run with: python compare_defenses.py              (runs all configs, ~10 minutes)
      or: python compare_defenses.py --from-saved (newest saved run per config, no model calls)

Raw runs stay in results/ (not committed); the table goes to findings/ (committed),
with the 9 runs behind it copied to findings/runs/.
"""

import argparse
import csv
import io
import json
import re
import shutil
from datetime import datetime
from pathlib import Path

from ingest import ATTACKS_DIR
from rag import normalize_defenses
from run_attacks import CASES_FILE, RESULTS_DIR, corpus_fingerprint, run_suite
from score_results import score_run, verdict_label

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


def latest_saved_run(defenses) -> tuple[Path, dict]:
    """The newest saved run for these defenses (exact label match), and its file."""
    pattern = re.compile(rf"attacks_{re.escape(run_label(defenses))}_\d{{8}}-\d{{6}}\.json")
    files = [p for p in RESULTS_DIR.glob("attacks_*.json") if pattern.fullmatch(p.name)]
    if not files:
        raise FileNotFoundError(f"no saved run for {run_label(defenses)}: run without --from-saved")
    path = max(files, key=lambda p: p.stat().st_mtime)
    return path, json.loads(path.read_text(encoding="utf-8"))


# Settings that must match for runs to be comparable (defenses and start time may differ).
# Runs made before corpus_fingerprint existed don't have it; "missing" matches "missing".
BENCHMARK_SETTINGS = (
    "chat_model", "embed_model", "model_digests", "k", "temperature", "seed", "corpus_fingerprint",
)


def _questions(results: dict) -> set[tuple[str, str]]:
    return {(c["id"], a["question"]) for c in results["cases"] for a in c["answers"]}


def _attack_docs(results: dict) -> dict[str, str | None]:
    return {c["id"]: c.get("attack_doc") for c in results["cases"]}


def check_compatible(runs: dict[str, dict]) -> None:
    """Stop if the runs weren't made under the same settings and questions.

    Saved runs are picked per config, so a newer run with another model version,
    k or question set could otherwise make a defense look better or worse.
    """
    reference = runs["none"]
    for name, results in runs.items():
        for key in BENCHMARK_SETTINGS:
            if results["settings"].get(key) != reference["settings"].get(key):
                raise ValueError(f"run for '{name}' has a different {key} than the baseline")
        if _questions(results) != _questions(reference):
            raise ValueError(f"run for '{name}' asked different questions than the baseline")
        if _attack_docs(results) != _attack_docs(reference):
            raise ValueError(f"run for '{name}' used different attack docs than the baseline")


def corpus_verified(runs: dict[str, dict]) -> bool:
    """True only if every run has the same, recorded corpus fingerprint.

    Older runs without a fingerprint still pass check_compatible ("missing"
    matches "missing"), but then nothing proves they used the same documents.
    """
    fingerprints = {r["settings"].get("corpus_fingerprint") for r in runs.values()}
    return len(fingerprints) == 1 and None not in fingerprints


def compare_outcomes(baseline: dict[tuple, bool], defense: dict[tuple, bool]) -> dict:
    """Match answers by (case, question) and count what changed.

    blocked: baseline wins the defense turned into non-wins.
    new_wins: attacks that failed in the baseline but succeed with the defense.
    """
    baseline_wins = {key for key, won in baseline.items() if won}
    defense_wins = {key for key, won in defense.items() if won}
    blocked = len(baseline_wins - defense_wins)
    return {
        "baseline_wins": len(baseline_wins),
        "blocked": blocked,
        # None when the baseline had no wins: nothing to block.
        "block_rate": round(blocked / len(baseline_wins), 2) if baseline_wins else None,
        "new_wins": len(defense_wins - baseline_wins),
    }


def summarize(results: dict) -> dict:
    """Counts for one run: outcomes per attack type, clean results, average latency."""
    rows = [r for r in score_run(results) if not r.get("unscored")]
    summary = {}
    for attack_type in ATTACK_TYPES:
        hits = [r for r in rows if r["type"] == attack_type]
        summary[attack_type] = {
            "wins": sum(r["success"] for r in hits),
            "tries": len(hits),
            "outcomes": {(r["case"], r["question"]): r["success"] for r in hits},
        }
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
            changes = compare_outcomes(baseline[attack_type]["outcomes"], s[attack_type]["outcomes"])
            rows.append({
                "config": name,
                "defenses": "+".join(normalize_defenses(CONFIGS[name])) or "none",
                "attack_type": attack_type,
                "wins": wins,
                "tries": tries,
                "attack_success_rate": round(wins / tries, 2) if tries else None,
                **changes,
                "clean_correct": s["clean"]["correct"],
                "clean_total": s["clean"]["total"],
                "false_alarms": s["clean"]["false_alarms"],
                "avg_latency_s": s["avg_latency_s"],
            })
    return rows


def _cell(row: dict) -> str:
    blocked = "n/a" if row["baseline_wins"] == 0 else f"{row['blocked']}/{row['baseline_wins']}"
    return f"{row['wins']}/{row['tries']} blk {blocked} new {row['new_wins']}"


def print_table(rows: list[dict]) -> None:
    print("cells: wins/tries · blk = baseline wins blocked · new = wins the baseline didn't have\n")
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


def answer_verdicts(results: dict) -> list[dict]:
    """Each answer's verdict, scored now with the same rules as the table's counts."""
    return [
        {"case": r["case"], "question": r["question"], "verdict": verdict_label(r)}
        for r in score_run(results)
        if not r.get("unscored")
    ]


def attack_doc_snapshots(runs: dict[str, dict]) -> dict[str, str]:
    """The text of every attack doc the runs used, saved so the page shows what ran.

    Only safe if the files haven't changed since the runs, so the current files
    must still match the runs' corpus fingerprint.
    """
    recorded = runs["none"]["settings"].get("corpus_fingerprint")
    if recorded is None or recorded != corpus_fingerprint():
        raise ValueError(
            "the documents changed since these runs (or the runs have no fingerprint), "
            "so their attack docs can't be snapshotted: run without --from-saved"
        )
    names = {c["attack_doc"] for run in runs.values() for c in run["cases"] if c.get("attack_doc")}
    return {name: (ATTACKS_DIR / name).read_text(encoding="utf-8") for name in sorted(names)}


def _write_atomic(path: Path, text: str) -> None:
    """Write to a temporary file, then rename it into place: all or nothing."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def publish(report: dict, paths: dict[str, Path]) -> None:
    """Save the findings so a failure can never leave the report pointing at missing runs.

    1. copy the new runs into findings/runs/ (next to the old ones),
    2. write the report and CSV atomically,
    3. only then delete run copies the new report no longer uses.
    """
    runs_dir = FINDINGS_DIR / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    for path in paths.values():
        target = runs_dir / path.name
        if path.resolve() != target.resolve():
            shutil.copy2(path, target)

    _write_atomic(FINDINGS_DIR / "defense_comparison.json",
                  json.dumps(report, indent=2, ensure_ascii=False))
    table = io.StringIO()
    writer = csv.DictWriter(table, fieldnames=list(report["rows"][0]))
    writer.writeheader()
    writer.writerows(report["rows"])
    _write_atomic(FINDINGS_DIR / "defense_comparison.csv", table.getvalue())

    in_use = set(report["sources"].values())
    for old in runs_dir.glob("attacks_*.json"):
        if old.name not in in_use:
            old.unlink()


def build_report(rows, runs, sources, verified) -> dict:
    """Everything the Attack Lab page shows, taken from these runs at this moment."""
    return {
        "generated": datetime.now().isoformat(timespec="seconds"),
        # False = the runs can't prove they used identical documents (see corpus_verified).
        "corpus_verified": verified,
        # Shared by every run (checked by check_compatible).
        "settings": {k: runs["none"]["settings"].get(k) for k in BENCHMARK_SETTINGS},
        "configs": {name: list(normalize_defenses(d)) for name, d in CONFIGS.items()},
        "sources": sources,  # which saved run file each config's numbers came from
        "rows": rows,
        # Per-answer verdicts and attack doc texts, so the drill-down always matches
        # the table even after detector rules or documents change later.
        "verdicts": {name: answer_verdicts(run) for name, run in runs.items()},
        "attack_docs": attack_doc_snapshots(runs),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compare the defenses.")
    parser.add_argument("--from-saved", action="store_true", help="use saved runs, no model calls")
    from_saved = parser.parse_args().from_saved

    cases = json.loads(CASES_FILE.read_text(encoding="utf-8"))
    runs, sources, paths = {}, {}, {}
    for name, defenses in CONFIGS.items():
        if from_saved:
            path, runs[name] = latest_saved_run(defenses)
        else:
            print(f"\n=== {name} ===")
            runs[name] = run_suite(cases, defenses)
            RESULTS_DIR.mkdir(exist_ok=True)
            path = RESULTS_DIR / f"attacks_{run_label(defenses)}_{datetime.now():%Y%m%d-%H%M%S}.json"
            path.write_text(json.dumps(runs[name], indent=2, ensure_ascii=False), encoding="utf-8")
        sources[name], paths[name] = path.name, path

    check_compatible(runs)
    rows = build_rows({name: summarize(run) for name, run in runs.items()})
    verified = corpus_verified(runs)
    print()
    print_table(rows)
    if not verified:
        print("\nWARNING: unverified: not every run recorded the same corpus fingerprint.")
    publish(build_report(rows, runs, sources, verified), paths)
    print(f"\nSaved {FINDINGS_DIR / 'defense_comparison.json'} and .csv")
