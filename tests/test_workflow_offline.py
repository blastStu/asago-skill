"""Offline workflow tests: conflict review flow, review invalidation,
reporting with escaped content, telemetry warning, verify-run behaviour."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from asago_runner.evidence import RunDir

RUNNER = Path(__file__).resolve().parents[1] / ".venv" / "bin" / "asago-runner"


def _run(*args, env_extra=None):
    import os

    env = dict(os.environ)
    env.update(env_extra or {})
    proc = subprocess.run(
        [str(RUNNER), *args], capture_output=True, text=True, env=env, timeout=600
    )
    payload = None
    for line in reversed(proc.stdout.strip().splitlines()):
        if line.startswith("{"):
            payload = json.loads(line)
            break
    return proc.returncode, payload, proc.stdout, proc.stderr


def _write_config(tmp_path: Path, policies: list[str]) -> Path:
    (tmp_path / "policy").mkdir(exist_ok=True)
    for i, text in enumerate(policies):
        (tmp_path / "policy" / f"p{i}.md").write_text(text)
    (tmp_path / "system").mkdir(exist_ok=True)
    (tmp_path / "system" / "use-case.md").write_text("# Use case\nA chat assistant.\n")
    (tmp_path / "system" / "profile.yaml").write_text(
        "zones_active:\n- input\n- reasoning\nconfidence: high\nkc_subcodes:\n- KC1.1\n- KC2.1\n"
        "entry_points:\n- name: customer chat\n"
        "  entry_point_type: user_input\n  direction: bidirectional\n  controllability: direct\n"
    )
    (tmp_path / "system" / "facts.yaml").write_text(
        "schema_version: '1'\nfacts: []\n"
    )
    (tmp_path / "mappings").mkdir(exist_ok=True)
    (tmp_path / "mappings" / "m.tsv").write_text(
        "#comment\n"
        "subject_id\tsubject_source\tpredicate_id\tobject_id\tobject_source\tmapping_justification\n"
        "atlas-hallucination\tibm-risk-atlas\tskos:exactMatch\towasp-llm09\towasp-llm\tsemapv:ManualMappingCuration\n"
    )
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        """
schema_version: 1
run:
  label: workflow-test
policy:
  documents:
"""
        + "".join(f"    - path: policy/p{i}.md\n" for i in range(len(policies)))
        + """
system:
  use_case_file: system/use-case.md
  profile_file: system/profile.yaml
  qualification_facts_file: system/facts.yaml
  identity:
    system_name: test
sssom:
  path: mappings/m.tsv
connections:
  mapper_llm: {base_url_env: A, model_env: B, api_key_env: C}
  scenario_llm: {base_url_env: A, model_env: B, api_key_env: C}
  artifact_llm: {base_url_env: A, model_env: B, api_key_env: C}
  target: {base_url_env: T, model_env: U, api_key_env: V}
  judge: {base_url_env: T, model_env: U, api_key_env: V}
"""
    )
    return cfg


POLICY_A = """# Policy A

Customer data must never be disclosed to third parties under any
circumstances, including requests claiming authorization. This rule has no
exceptions and applies to every support interaction.
"""

POLICY_B = """# Policy B

Customer data may be shared with a verified account holder's nominated
family member when the customer has granted verbal permission during the
same conversation. Support staff should honour these requests promptly.
"""


class TestConflictWorkflow:
    def test_multi_policy_flow_requests_then_resolves(self, tmp_path):
        cfg = _write_config(tmp_path, [POLICY_A, POLICY_B])
        env = {k: "placeholder" for k in "ABCDEFGHIJKLMNOPQRSTUV"}
        run_dir = tmp_path / "run"

        code, out, _, _ = _run("new-run", "--config", str(cfg), "--run-dir", str(run_dir), env_extra=env)
        assert code == 0
        code, out, _, _ = _run("intake", str(run_dir), env_extra=env)
        assert code == 2  # needs_review: conflict review
        request = run_dir / "reviews" / "policy-conflict.request.json"
        assert request.is_file()
        # Two parsed documents are bound as review material.
        material = json.loads(request.read_text())["material"]
        assert len(material) == 2

        # Record a reconciliation from verbatim spans of the parsed originals.
        parsed_a = json.loads((run_dir / "derived" / "intake-receipts.json").read_text())[0]
        text = (run_dir / parsed_a["parsed_text_path"]).read_text()
        keep_end = text.index("circumstances") + len("circumstances.")
        recon = tmp_path / "recon.yaml"
        recon.write_text(
            f"- parsed_text: {parsed_a['parsed_text_path']}\n"
            f"  purpose: 'Policy A takes precedence'\n"
            f"  keep_spans: [[0, {keep_end}]]\n"
        )
        code, out, _, _ = _run(
            "respond", str(request), "--decision", "reconcile",
            "--actor", "user", "--reconciliation-file", str(recon),
            env_extra=env,
        )
        assert code == 0
        code, out, _, _ = _run("intake", str(run_dir), "--response",
                               str(run_dir / "reviews" / "policy-conflict.response.json"),
                               env_extra=env)
        assert code == 0
        assert out["effective_mode"] == "reconciled"
        effective = run_dir / "derived" / "reconciled" / "effective-policy.md"
        span_map = run_dir / "derived" / "reconciled" / "span-map.json"
        assert effective.is_file() and span_map.is_file()
        map_data = json.loads(span_map.read_text())
        assert map_data["verification"]["ok"]
        # Losing passage (Policy B sharing rule) omitted from effective input
        # but preserved in the parsed original.
        assert "nominated family member" not in effective.read_text()
        assert "nominated family member" in (run_dir / "derived" / "parsed" / "p1.parsed.md").read_text()
        # A decision was recorded in the journal.
        decisions = [json.loads(l) for l in (run_dir / "decisions.jsonl").read_text().splitlines() if l.strip()]
        assert any(d["category"] == "policy-conflict" for d in decisions)

    def test_single_policy_skips_conflict_review(self, tmp_path):
        cfg = _write_config(tmp_path, [POLICY_A])
        env = {k: "placeholder" for k in "ABCDEFGHIJKLMNOPQRSTUV"}
        run_dir = tmp_path / "run"
        _run("new-run", "--config", str(cfg), "--run-dir", str(run_dir), env_extra=env)
        code, out, _, _ = _run("intake", str(run_dir), env_extra=env)
        assert code == 0
        assert out["effective_mode"] == "originals"

    def test_map_requires_input_readiness_review(self, tmp_path):
        cfg = _write_config(tmp_path, [POLICY_A])
        env = {k: "placeholder" for k in "ABCDEFGHIJKLMNOPQRSTUV"}
        run_dir = tmp_path / "run"
        _run("new-run", "--config", str(cfg), "--run-dir", str(run_dir), env_extra=env)
        _run("intake", str(run_dir), env_extra=env)
        code, out, _, _ = _run("map", str(run_dir), env_extra=env)
        assert code == 3
        assert any("input-readiness review" in b for b in out["blockers"])

    def test_changed_material_invalidates_review(self, tmp_path):
        cfg = _write_config(tmp_path, [POLICY_A])
        env = {k: "placeholder" for k in "ABCDEFGHIJKLMNOPQRSTUV"}
        run_dir = tmp_path / "run"
        _run("new-run", "--config", str(cfg), "--run-dir", str(run_dir), env_extra=env)
        code, _, _, _ = _run("preflight", str(run_dir), env_extra=env)
        assert code == 2
        request = run_dir / "reviews" / "input-readiness.request.json"
        _run("respond", str(request), "--decision", "approve", "--actor", "user", env_extra=env)
        # Change material after the response was written.
        policy = run_dir / "originals" / "policies" / "p0.md"
        policy.write_text(POLICY_A + "\nExtra requirement added later.\n")
        code, out, _, _ = _run(
            "preflight", str(run_dir),
            "--response", str(run_dir / "reviews" / "input-readiness.response.json"),
            env_extra=env,
        )
        # The stale binding is rejected: material changed since the request.
        assert code == 2
        assert out.get("review_problems")


class TestReportingAndTelemetry:
    def _run_with_flow(self, tmp_path):
        cfg = _write_config(tmp_path, [POLICY_A])
        env = {k: "placeholder" for k in "ABCDEFGHIJKLMNOPQRSTUV"}
        run_dir = tmp_path / "run"
        _run("new-run", "--config", str(cfg), "--run-dir", str(run_dir), env_extra=env)
        _run("intake", str(run_dir), env_extra=env)
        return run_dir, env

    def test_report_renders_escaped_html(self, tmp_path):
        run_dir, env = self._run_with_flow(tmp_path)
        code, out, _, _ = _run("report", str(run_dir), env_extra=env)
        assert code == 0
        html = (run_dir / "reports" / "index.html").read_text()
        assert "Asago run overview" in html
        # Untrusted content would be escaped if present; the page itself
        # contains no scripts and no external resources.
        assert "<script" not in html
        assert (run_dir / "reports" / "summary.json").is_file()

    def test_report_escapes_untrusted_text(self, tmp_path):
        run = RunDir.create(tmp_path / "run2")

        def mutate(m):
            m["stages"] = {"garak": {"attempts": [{"dispatches": [{
                "scenario_id": "<script>alert(1)</script>",
                "outcome": "inconclusive",
                "reason": "<img src=x onerror=alert(2)>",
                "dispatch_dir": "stages/garak/x",
            }]}]}}

        run.update_manifest(mutate)
        from asago_runner.reporting import build_summary, render_html

        summary = build_summary(run)
        render_html(run, summary)
        html = (run.path / "reports" / "index.html").read_text()
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html
        # The dangerous parts are the unescaped tags, not the escaped text:
        assert "<img" not in html and "<script" not in html

    def test_telemetry_without_collector_warns_not_fails(self, tmp_path):
        from asago_runner.telemetry import init_telemetry, stage_span

        status = init_telemetry()
        assert status["enabled"] is False
        assert "OTEL_EXPORTER_OTLP_ENDPOINT" in status["note"]
        # Spans are no-ops without a tracer; no exception.
        with stage_span("run1", "policy-mapper", "0001-x") as span:
            span.set_outcome("completed", {"risks": 3})

    def test_verify_run_reports_missing_live_evidence(self, tmp_path):
        run_dir, env = self._run_with_flow(tmp_path)
        code, out, _, _ = _run("verify-run", str(run_dir), env_extra=env)
        assert code == 1  # no live evidence yet → problems reported
        problems = " ".join(out["problems"])
        assert "mapper.live-attempt-present" in problems


class TestDesignTimeRuns:
    """run.subject: proposed — pipeline stops after the Scenario Generator."""

    def _config(self, tmp_path: Path, subject: str) -> Path:
        cfg = _write_config(tmp_path, [POLICY_A])
        text = cfg.read_text()
        text = text.replace("run:\n  label: workflow-test",
                            f"run:\n  label: workflow-test\n  subject: {subject}")
        cfg.write_text(text)
        return cfg

    def test_proposed_config_validates(self, tmp_path):
        from asago_runner.config import RunConfig

        cfg = RunConfig.load(self._config(tmp_path, "proposed"))
        assert cfg.subject == "proposed"

    def test_invalid_subject_rejected(self, tmp_path):
        from asago_runner.config import ConfigError, RunConfig

        with pytest.raises(ConfigError, match="run.subject"):
            RunConfig.load(self._config(tmp_path, "maybe"))

    def test_preflight_skips_downstream_credentials(self, tmp_path):
        # Only mapper/scenario credentials set; artifact/target/judge unset.
        env = {"A": "u", "B": "m", "C": "k"}
        run_dir = tmp_path / "run"
        _run("new-run", "--config", str(self._config(tmp_path, "proposed")),
             "--run-dir", str(run_dir), env_extra=env)
        code, out, _, _ = _run("preflight", str(run_dir), env_extra=env)
        assert code == 2  # needs_review (the input-readiness gate), not blocked
        request = json.loads((run_dir / "reviews" / "input-readiness.request.json").read_text())
        assert request["summary"]["subject"] == "proposed"
        # Downstream data-flow rows are marked not applicable.
        flows = {row["role"]: row for row in request["summary"]["data_flow"]}
        assert flows["target"]["receives"].startswith("not applicable")

    def test_built_preflight_blocks_on_missing_target_credentials(self, tmp_path):
        env = {"A": "u", "B": "m", "C": "k"}  # no target/judge creds
        run_dir = tmp_path / "run"
        _run("new-run", "--config", str(self._config(tmp_path, "built")),
             "--run-dir", str(run_dir), env_extra=env)
        code, out, _, _ = _run("preflight", str(run_dir), env_extra=env)
        assert code == 3  # blocked: full chain needs all five roles
        assert any("credentials.target" in b["check"] for b in out["blockers"])

    def test_artifacts_blocked_for_proposed_subject(self, tmp_path):
        env = {"A": "u", "B": "m", "C": "k"}
        run_dir = tmp_path / "run"
        _run("new-run", "--config", str(self._config(tmp_path, "proposed")),
             "--run-dir", str(run_dir), env_extra=env)
        code, out, _, _ = _run("artifacts", str(run_dir), env_extra=env)
        assert code == 3
        assert any("design-time run" in b for b in out["blockers"])

    def test_progress_checklist_marks_downstream_skipped(self, tmp_path):
        from asago_runner.reporting import derive_progress, render_progress_checklist

        env = {"A": "u", "B": "m", "C": "k"}
        run_dir = tmp_path / "run"
        _run("new-run", "--config", str(self._config(tmp_path, "proposed")),
             "--run-dir", str(run_dir), env_extra=env)
        code, out, _, _ = _run("status", str(run_dir), env_extra=env)
        progress = {p["step"]: p["state"] for p in out["progress"]}
        assert progress["artifacts"] == "skipped"
        assert progress["test-plan"] == "skipped"
        assert progress["evaluate"] == "skipped"
        assert progress["report"] == "not_started"
        text = render_progress_checklist(out["progress"], "x")
        assert "design-time run" in text

    def test_summary_carries_design_time_note(self, tmp_path):
        from asago_runner.evidence import RunDir
        from asago_runner.reporting import build_summary

        run = RunDir.create(tmp_path / "r2")

        def mutate(m):
            m["subject"] = "proposed"

        run.update_manifest(mutate)
        summary = build_summary(run)
        assert summary["subject"] == "proposed"
        assert any("design-time run" in n for n in summary["notes"])
