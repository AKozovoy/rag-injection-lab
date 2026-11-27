"""Runner tests that don't need Ollama: model calls are swapped for stand-ins."""

import run_attacks


def _stub(monkeypatch, scanned_before: bool) -> list[dict]:
    """Replace Ollama/Chroma calls; return a list that records each rebuild."""
    rebuilds = []
    # monkeypatch replaces a function for this test only, then restores it.
    monkeypatch.setattr(run_attacks, "model_digests", lambda: {})
    monkeypatch.setattr(
        run_attacks, "build_index",
        lambda attacks=None, scan=False: rebuilds.append({"attacks": attacks, "scan": scan}) or 0,
    )
    monkeypatch.setattr(
        run_attacks, "index_scan_info", lambda: {"scan": scanned_before, "quarantined": []}
    )
    return rebuilds


def test_run_suite_records_normalized_defenses(monkeypatch):
    _stub(monkeypatch, scanned_before=False)
    results = run_attacks.run_suite([], ["spotlight", "spotlight_datamark"])
    assert results["settings"]["defenses"] == ["spotlight_datamark"]


def test_cleanup_keeps_the_ui_scan_setting(monkeypatch):
    rebuilds = _stub(monkeypatch, scanned_before=True)
    run_attacks.run_suite([], [])
    assert rebuilds[-1] == {"attacks": None, "scan": True}  # no attack docs, scanning kept
