"""Optional Policy Mapper concurrency throttle (options.mapper_max_concurrent)."""

from __future__ import annotations

import pytest

from asago_runner.adapters.mapper import build_mapper_argv
from asago_runner.config import ConfigError, RunConfig


def _config(tmp_path, options: str = "") -> RunConfig:
    (tmp_path / "policy").mkdir(exist_ok=True)
    (tmp_path / "policy" / "p.md").write_text("# Policy\n")
    (tmp_path / "system").mkdir(exist_ok=True)
    (tmp_path / "system" / "use.md").write_text("# Use case\n")
    (tmp_path / "mappings").mkdir(exist_ok=True)
    (tmp_path / "mappings" / "m.tsv").write_text(
        "subject_id\tsubject_source\tpredicate_id\tobject_id\tobject_source\t"
        "mapping_justification\n"
    )
    path = tmp_path / "config.yaml"
    path.write_text(
        """
schema_version: 1
run:
  label: mapper-concurrency-test
  subject: proposed
policy:
  documents:
    - path: policy/p.md
system:
  use_case_file: system/use.md
  identity:
    system_name: concurrency-test
sssom:
  path: mappings/m.tsv
connections:
  mapper_llm: {base_url_env: MB, model_env: MM, api_key_env: MK}
  scenario_llm: {base_url_env: MB, model_env: MM, api_key_env: MK}
"""
        + options
    )
    return RunConfig.load(path)


def _argv(config: RunConfig):
    argv, _env = build_mapper_argv(
        config,
        [config.source_path.parent / "policy" / "p.md"],
        config.source_path.parent / "out",
        config.source_path.parent / "nexus",
    )
    return argv


def test_absent_option_preserves_component_default(tmp_path, monkeypatch):
    monkeypatch.setenv("MB", "https://example.invalid/v1")
    monkeypatch.setenv("MM", "test-model")
    monkeypatch.setenv("MK", "not-needed")
    argv = _argv(_config(tmp_path))
    assert "--max-concurrent" not in argv


def test_configured_value_is_passed_once_and_adjacent(tmp_path, monkeypatch):
    monkeypatch.setenv("MB", "https://example.invalid/v1")
    monkeypatch.setenv("MM", "test-model")
    monkeypatch.setenv("MK", "not-needed")
    cfg = _config(tmp_path, "\noptions:\n  mapper_max_concurrent: 4\n")
    argv = _argv(cfg)
    assert argv.count("--max-concurrent") == 1
    index = argv.index("--max-concurrent")
    assert argv[index + 1] == "4"


@pytest.mark.parametrize("value", ["null", "'none'", "'unlimited'", '""'])
def test_null_none_and_empty_are_treated_as_absent(tmp_path, monkeypatch, value):
    monkeypatch.setenv("MB", "https://example.invalid/v1")
    monkeypatch.setenv("MM", "test-model")
    monkeypatch.setenv("MK", "not-needed")
    text = f"\noptions:\n  mapper_max_concurrent: {value}\n"
    argv = _argv(_config(tmp_path, text))
    assert "--max-concurrent" not in argv


@pytest.mark.parametrize("value", ["0", "-1", "'four'"])
def test_invalid_values_are_rejected(tmp_path, value):
    with pytest.raises(ConfigError, match="mapper_max_concurrent"):
        _config(tmp_path, f"\noptions:\n  mapper_max_concurrent: {value}\n")


def test_snapshot_records_the_throttle(tmp_path, monkeypatch):
    monkeypatch.setenv("MB", "https://example.invalid/v1")
    monkeypatch.setenv("MM", "test-model")
    monkeypatch.setenv("MK", "not-needed")
    cfg = _config(tmp_path, "\noptions:\n  mapper_max_concurrent: 4\n")
    assert cfg.sanitized_snapshot()["options"]["mapper_max_concurrent"] == 4
    assert cfg.mapper_max_concurrent == 4
