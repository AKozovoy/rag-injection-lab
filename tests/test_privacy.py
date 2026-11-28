"""The app's usage statistics stay off (Chroma and Streamlit)."""

import tomllib
from pathlib import Path

import vectorstore


def test_chroma_telemetry_is_off(monkeypatch, tmp_path):
    monkeypatch.setattr(vectorstore, "CHROMA_DIR", tmp_path)
    assert vectorstore._client().get_settings().anonymized_telemetry is False


def test_streamlit_usage_stats_are_off():
    config = Path(__file__).parent.parent / ".streamlit" / "config.toml"
    settings = tomllib.loads(config.read_text(encoding="utf-8"))
    assert settings["browser"]["gatherUsageStats"] is False
