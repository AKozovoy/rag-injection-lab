"""Runner tests that don't need Ollama: model calls are swapped for stand-ins."""

import run_attacks


def test_run_suite_records_normalized_defenses(monkeypatch):
    # monkeypatch replaces a function for this test only, then restores it.
    monkeypatch.setattr(run_attacks, "model_digests", lambda: {})
    monkeypatch.setattr(run_attacks, "build_index", lambda attacks=None: 0)

    results = run_attacks.run_suite([], ["spotlight", "spotlight_datamark"])
    assert results["settings"]["defenses"] == ["spotlight_datamark"]
