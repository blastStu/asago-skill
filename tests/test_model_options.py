"""Detection of the agent's own model connection (no secrets, no assumptions)."""

from __future__ import annotations

import json
import os
import subprocess

from asago_runner.model_options import detect_model_options, render_model_options

RUNNER = None
from pathlib import Path

RUNNER = str(Path(__file__).resolve().parents[1] / ".venv" / "bin" / "asago-runner")


def _clean_env(monkeypatch):
    for name in (
        "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
        "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_HAIKU_MODEL",
        "OPENAI_BASE_URL", "OPENAI_API_KEY", "OPENAI_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)


def test_nothing_detected_when_environment_is_bare(monkeypatch):
    _clean_env(monkeypatch)
    detected = detect_model_options()
    assert detected["candidates"] == []
    assert "None detected" in render_model_options(detected)


def test_detects_anthropic_style_agent_without_secret(monkeypatch):
    _clean_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://gateway.example.com")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-super-secret-value")
    monkeypatch.setenv("ANTHROPIC_DEFAULT_SONNET_MODEL", "some-model")
    detected = detect_model_options()
    assert len(detected["candidates"]) == 1
    candidate = detected["candidates"][0]
    assert candidate["base_url_host"] == "gateway.example.com"
    assert candidate["model"] == "some-model"
    assert candidate["api_key_present"] is True
    assert candidate["api_key_env"] == "ANTHROPIC_API_KEY"
    # The secret value never appears in the description or JSON.
    rendered = render_model_options(detected)
    assert "sk-super-secret-value" not in rendered
    assert "sk-super-secret-value" not in json.dumps(detected)


def test_anthropic_host_is_assessed_unlikely(monkeypatch):
    _clean_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    detected = detect_model_options()
    assert detected["candidates"][0]["openai_compat"] == "unlikely"


def test_openai_host_is_assessed_likely(monkeypatch):
    _clean_env(monkeypatch)
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o-mini")
    detected = detect_model_options()
    candidate = detected["candidates"][0]
    assert candidate["source"] == "openai-style agent"
    assert candidate["openai_compat"] == "likely"


def test_command_outputs_json_and_no_secrets(monkeypatch):
    _clean_env(monkeypatch)
    env = {
        **os.environ,
        "ANTHROPIC_BASE_URL": "https://gateway.example.com",
        "ANTHROPIC_API_KEY": "sk-super-secret-value",
    }
    proc = subprocess.run(
        [RUNNER, "model-options"], capture_output=True, text=True, env=env
    )
    assert proc.returncode == 0
    assert "sk-super-secret-value" not in proc.stdout
    assert "sk-super-secret-value" not in proc.stderr
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["status"] == "completed"
    assert payload["candidates"][0]["base_url_host"] == "gateway.example.com"
    # And it is framed as an option, not an assumption.
    assert "never select one silently" in payload["note"]
