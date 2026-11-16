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
        assert "From policy to model evaluation." in html
        assert "Asago run report" in html
        # The page is self-contained: one inline script for filters and stage
        # navigation, and no external resources of any kind.
        assert "<script src" not in html
        assert "<link " not in html
        assert "http://" not in html and "https://" not in html
        assert (run_dir / "reports" / "summary.json").is_file()

    def test_report_escapes_untrusted_text(self, tmp_path):
        run = RunDir.create(tmp_path / "run2")

        def mutate(m):
            m["stages"] = {"garak": {"status": "completed", "attempts": [{"dispatches": [{
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
        # The dangerous parts are the unescaped tags, not the escaped text.
        assert "<img" not in html and "<script>alert" not in html

    def test_report_groups_risks_by_theme(self, tmp_path):
        from asago_runner.evidence import RunDir
        from asago_runner.reporting import build_summary, render_html

        run = RunDir.create(tmp_path / "themed")
        sssom = run.path / "originals" / "sssom" / "risk_to_category.sssom.tsv"
        sssom.parent.mkdir(parents=True)
        sssom.write_text(
            "#curie_map:\nsubject_id\tsubject_source\tpredicate_id\tobject_id\t"
            "object_source\tmapping_justification\n"
            "atlas-example\tibm-risk-atlas\tskos:exactMatch\tnist-data-privacy\t"
            "nist-ai-rmf\texample\n",
            encoding="utf-8",
        )
        attempt = run.path / "stages" / "policy-mapper" / "0001-x"
        attempt.mkdir(parents=True)
        (attempt / "risk-extraction.json").write_text(
            json.dumps(
                {
                    "risks": [
                        {
                            "risk_id": "atlas-example",
                            "risk_name": "Example privacy risk",
                            "risk_description": "Description",
                            "taxonomy": "ibm-risk-atlas",
                            "grounding_confidence": "high",
                            "evidence": [
                                {
                                    "text": "The policy protects personal data.",
                                    "document": "/elsewhere/policy.pdf",
                                    "section": "Data",
                                }
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        def mutate(m):
            m["subject"] = "built"
            m["stages"] = {
                "policy-mapper": {
                    "status": "completed",
                    "attempts": [{"attempt_id": "0001-x", "status": "completed"}],
                }
            }
            m["flow"] = {
                "mapper_output": {
                    "extraction": "stages/policy-mapper/0001-x/risk-extraction.json"
                }
            }

        run.update_manifest(mutate)
        summary = build_summary(run)
        from asago_runner.report_page import collect_report_data

        details = collect_report_data(run, summary)
        assert details["policy"]["counts"]["themes"] == {"privacy": 1}
        render_html(run, summary)
        html = (run.path / "reports" / "index.html").read_text()
        assert "Privacy &amp; confidentiality" in html
        assert "data-theme='privacy'" in html
        assert "The policy protects personal data." in html
        # Untrusted document paths are shown as a basename, not an absolute path.
        assert "/elsewhere/policy.pdf" not in html and "policy.pdf" in html

    def test_report_disables_unrun_design_stages(self, tmp_path):
        from asago_runner.evidence import RunDir
        from asago_runner.reporting import build_summary, render_html

        run = RunDir.create(tmp_path / "design")
        run.update_manifest(
            lambda m: m.update(
                {
                    "subject": "proposed",
                    "stages": {"policy-mapper": {"status": "completed"}},
                }
            )
        )
        summary = build_summary(run)
        render_html(run, summary)
        html = (run.path / "reports" / "index.html").read_text()
        assert "Not run — design-time" in html
        assert "disabled" in html
        assert "panel-artifact" not in html and "panel-evaluation" not in html
        assert "panel-policy" in html

    def test_report_includes_conversation_and_audit(self, tmp_path):
        from asago_runner.evidence import RunDir
        from asago_runner.reporting import build_summary, render_html

        run = RunDir.create(tmp_path / "audited")
        summary = build_summary(run)
        render_html(run, summary, "# Session\nWe ran **report**.\n- step one")
        html = (run.path / "reports" / "index.html").read_text()
        assert "Conversation with the agent" in html
        assert "<strong>report</strong>" in html
        assert "<li>step one</li>" in html
        assert "Run audit" in html
        # Transcript content is rendered, not copied into the machine summary.
        assert "step one" in html
        assert "step one" not in (run.path / "reports" / "summary.json").read_text()

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


class TestRunIsolation:
    """New runs default outside the repo, under a configurable root."""

    def test_default_run_goes_to_runs_root(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASAGO_RUNNER_RUNS_ROOT", str(tmp_path / "root"))
        cfg = _write_config(tmp_path, [POLICY_A])
        env = {k: "placeholder" for k in "ABCDEFGHIJKLMNOPQRSTUV"}
        code, out, _, _ = _run("new-run", "--config", str(cfg), env_extra=env)
        assert code == 0
        # Label-derived name under the root, not under ./runs in cwd
        assert out["run_dir"].startswith(str(tmp_path / "root"))
        assert "/runs/" not in out["run_dir"].replace(str(tmp_path / "root"), "")
        assert (tmp_path / "root" / "workflow-test").is_dir()

    def test_same_label_collision_gets_unique_suffix(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASAGO_RUNNER_RUNS_ROOT", str(tmp_path / "root"))
        cfg = _write_config(tmp_path, [POLICY_A])
        env = {k: "placeholder" for k in "ABCDEFGHIJKLMNOPQRSTUV"}
        _run("new-run", "--config", str(cfg), env_extra=env)
        code, out, _, _ = _run("new-run", "--config", str(cfg), env_extra=env)
        assert code == 0
        assert out["run_dir"] != str(tmp_path / "root" / "workflow-test")
        # The first run is untouched.
        assert (tmp_path / "root" / "workflow-test" / "run.json").is_file()

    def test_runs_root_flag_overrides_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASAGO_RUNNER_RUNS_ROOT", str(tmp_path / "env-root"))
        cfg = _write_config(tmp_path, [POLICY_A])
        env = {k: "placeholder" for k in "ABCDEFGHIJKLMNOPQRSTUV"}
        code, out, _, _ = _run("new-run", "--config", str(cfg),
                               "--runs-root", str(tmp_path / "flag-root"),
                               env_extra=env)
        assert code == 0
        assert out["run_dir"].startswith(str(tmp_path / "flag-root"))

    def test_stages_never_touch_sibling_runs(self, tmp_path, monkeypatch):
        """Two runs in the same root stay independent."""
        monkeypatch.setenv("ASAGO_RUNNER_RUNS_ROOT", str(tmp_path / "root"))
        cfg = _write_config(tmp_path, [POLICY_A])
        env = {k: "placeholder" for k in "ABCDEFGHIJKLMNOPQRSTUV"}
        _, first, _, _ = _run("new-run", "--config", str(cfg), env_extra=env)
        _, second, _, _ = _run("new-run", "--config", str(cfg), env_extra=env)
        run_a, run_b = first["run_dir"], second["run_dir"]
        # Progress on run B leaves run A's manifest untouched.
        _run("intake", run_b, env_extra=env)
        import json as j

        manifest_a = j.loads((Path(run_a) / "run.json").read_text())
        assert "effective_inputs" not in manifest_a.get("flow", {})
        assert "effective_inputs" in j.loads(
            (Path(run_b) / "run.json").read_text()
        )["flow"]


def _minimal_config(tmp_path: Path) -> Path:
    """A config with only the required inputs (no profile/facts)."""
    if True:
        (tmp_path / "policy").mkdir(exist_ok=True)
        (tmp_path / "policy" / "p.md").write_text(POLICY_A)
        (tmp_path / "system").mkdir(exist_ok=True)
        (tmp_path / "system" / "use-case.md").write_text("# Use case\nA chat assistant.\n")
        (tmp_path / "mappings").mkdir(exist_ok=True)
        (tmp_path / "mappings" / "m.tsv").write_text(
            "#c\nsubject_id\tsubject_source\tpredicate_id\tobject_id\tobject_source\tmapping_justification\n"
            "atlas-hallucination\tibm-risk-atlas\tskos:exactMatch\towasp-llm09\towasp-llm\tsemapv:ManualMappingCuration\n"
        )
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text(
            """schema_version: 1
run:
  label: minimal
policy:
  documents:
    - path: policy/p.md
system:
  use_case_file: system/use-case.md
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

    def test_config_without_profile_or_facts_is_valid(self, tmp_path):
        from asago_runner.config import RunConfig

        cfg = RunConfig.load(_minimal_config(tmp_path))
        assert cfg.raw["system"].get("profile_file") is None

    def test_preflight_notes_inference_when_profile_absent(self, tmp_path):
        env = {k: "placeholder" for k in "ABCDEFGHIJKLMNOPQRSTUV"}
        run_dir = tmp_path / "run"
        _run("new-run", "--config", str(_minimal_config(tmp_path)),
             "--run-dir", str(run_dir), env_extra=env)
        code, out, _, _ = _run("preflight", str(run_dir), env_extra=env)
        assert code == 2  # needs_review, not blocked on schema checks
        report = json.loads(
            (run_dir / "preflight" / "preflight.json").read_text()
        )
        checks = {c["check"]: c for c in report["checks"]}
        assert checks["scenario.profile-optional-absent"]["ok"] is True
        assert "Stage-1 inference" in checks["scenario.profile-optional-absent"]["detail"]
        assert checks["scenario.facts-optional-absent"]["ok"] is True

    def test_use_case_alone_still_required(self, tmp_path):
        from asago_runner.config import ConfigError, RunConfig

        cfg_path = self._minimal_config(tmp_path)
        text = cfg_path.read_text().replace(
            "system:\n  use_case_file: system/use-case.md", "system:\n"
        )
        cfg_path.write_text(text)
        with pytest.raises(ConfigError, match="use_case_file"):
            RunConfig.load(cfg_path)


class TestLogCommand:
    def test_log_tails_latest_attempt(self, tmp_path):
        env = {k: "placeholder" for k in "ABCDEFGHIJKLMNOPQRSTUV"}
        cfg = _write_config(tmp_path, [POLICY_A])
        run_dir = tmp_path / "run"
        _run("new-run", "--config", str(cfg), "--run-dir", str(run_dir), env_extra=env)
        # No attempts yet: exits cleanly with a note.
        code, out, _, err = _run("log", str(run_dir), env_extra=env)
        assert code == 0
        # Create a fake attempt with a log; log should tail it.
        attempt = run_dir / "stages" / "policy-mapper" / "0001-test"
        attempt.mkdir(parents=True)
        (attempt / "stderr.log").write_text(
            "\n".join(f"line {i}" for i in range(50)) + "\n"
        )
        proc = subprocess.run(
            [str(RUNNER), "log", str(run_dir), "--stage", "map", "--lines", "5"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0
        assert "line 49" in proc.stdout
        assert "line 40" not in proc.stdout  # only the tail


class TestAdversarialReviewFixes:
    """Regression tests for the 2026-11-13 adversarial review findings."""

    def test_rejection_does_not_resolve_gate(self, tmp_path):
        env = {k: "placeholder" for k in "ABCDEFGHIJKLMNOPQRSTUV"}
        cfg = _write_config(tmp_path, [POLICY_A])
        run_dir = tmp_path / "run"
        _run("new-run", "--config", str(cfg), "--run-dir", str(run_dir), env_extra=env)
        _run("preflight", str(run_dir), env_extra=env)  # writes the request
        request = run_dir / "reviews" / "input-readiness.request.json"
        req = json.loads(request.read_text())
        assert "reject" not in req["allowed_decisions"]
        _run("respond", str(request), "--decision", "reject",
             "--actor", "user", "--notes", "not yet", env_extra=env)
        code, out, _, _ = _run(
            "preflight", str(run_dir),
            "--response", str(run_dir / "reviews" / "input-readiness.response.json"),
            env_extra=env,
        )
        assert code == 2  # gate stays closed
        assert any("does not resolve" in p for p in out.get("review_problems", []))
        # The rejection is recorded in the journal.
        decisions = [
            json.loads(l) for l in (run_dir / "decisions.jsonl").read_text().splitlines() if l.strip()
        ]
        assert any(d.get("state") == "rejected" for d in decisions)
        # And the map stage is still blocked.
        code, out, _, _ = _run("map", str(run_dir), env_extra=env)
        assert code == 3

    def test_profile_free_generate_has_no_profile_flag(self, tmp_path, monkeypatch):
        from asago_runner.adapters import scenarios as scen

        captured = {}

        class FakeProc:
            returncode, timed_out = 0, False

        def fake_run_subprocess(argv, **kwargs):
            captured["argv"] = argv
            return FakeProc()

        monkeypatch.setattr(scen, "run_subprocess", fake_run_subprocess)
        from asago_runner.config import RunConfig

        cfg = RunConfig.load(_minimal_config(tmp_path))
        scen.run_generate(
            cfg, tmp_path,
            use_case_file=tmp_path / "u.md",
            risk_extraction=tmp_path / "r.json",
            sssom=tmp_path / "s.tsv",
            profile=None,
            qualification_facts=None,
            output_dir=tmp_path / "out",
        )
        argv = captured["argv"]
        assert "--profile" not in argv
        assert "None" not in [str(a) for a in argv]

    def test_facts_gate_parses_native_schema(self):
        from asago_runner.cli import _preflight_unresolved

        outcome = {
            "readiness": {"ready": False, "missing_facts": ["capabilities.code_interpreter"]},
            "fact_states": [
                {"fact": {"fact_id": "capabilities.retrieval_corpus"}, "status": "present", "required": True},
                {"fact": {"fact_id": "capabilities.feedback_loop"}, "status": "absent", "required": True},
            ],
        }
        unresolved = _preflight_unresolved(outcome)
        statuses = {(u.get("fact") or {}).get("fact_id", u.get("status")) for u in unresolved}
        assert "capabilities.feedback_loop" in statuses
        assert "capabilities.code_interpreter" in statuses
        assert "capabilities.retrieval_corpus" not in statuses

    def test_verify_run_design_time_scope(self, tmp_path):
        from asago_runner.evidence import RunDir
        from asago_runner.verify import verify_run

        run = RunDir.create(tmp_path / "r2")

        def mutate(m):
            m["subject"] = "proposed"

        run.update_manifest(mutate)
        report = verify_run(run, None)
        # No artifact checks fire for a design-time run; the report must
        # not claim missing replay entries.
        names = [c["check"] for c in report["checks"]]
        assert "artifact.replay-entries-present" not in names
        assert "design.subject-recorded" in names

    def test_span_map_separators_are_range_correct(self, tmp_path):
        from asago_runner.evidence import RunDir
        from asago_runner.intake import build_reconciled_input

        run = RunDir.create(tmp_path / "r3")
        parsed = run.path / "derived" / "parsed" / "a.parsed.md"
        parsed.parent.mkdir(parents=True, exist_ok=True)
        parsed.write_text("AAAABBBBCCCCDDDD")
        # Keep a receipt so the path validation accepts the source.
        (run.path / "derived" / "intake-receipts.json").write_text(
            json.dumps([{"parsed_text_path": "derived/parsed/a.parsed.md"}])
        )
        effective, span_map_path = build_reconciled_input(
            run,
            [{"parsed_text": "derived/parsed/a.parsed.md", "keep_spans": [[0, 4], [8, 12]]}],
        )
        effective_text = effective.read_text()
        assert effective_text == "AAAA\n\nCCCC"
        span_map = json.loads(span_map_path.read_text())
        assert span_map["verification"]["ok"]
        # The recorded effective range of span 2 contains exactly CCCC.
        second = span_map["spans"][1]
        start, end = second["effective_range"]
        assert effective_text[start:end] == "CCCC"
        assert second["effective_range"] == [6, 10]  # 4 + len(sep) = 6

    def test_reconciliation_rejects_paths_outside_parsed_dir(self, tmp_path):
        from asago_runner.evidence import RunDir
        from asago_runner.intake import IntakeError, build_reconciled_input

        run = RunDir.create(tmp_path / "r4")
        secret = tmp_path / "secret.md"
        secret.write_text("secret text here")
        with pytest.raises(IntakeError, match="not a recorded parsed text"):
            build_reconciled_input(
                run,
                [{"parsed_text": "../../secret.md", "keep_spans": [[0, 6]]}],
            )
        with pytest.raises(IntakeError, match="not a recorded parsed text"):
            build_reconciled_input(
                run,
                [{"parsed_text": str(secret), "keep_spans": [[0, 6]]}],
            )


class TestVerificationRound2:
    """Regressions for the 2026-11-14 fix-verification findings."""

    def test_adapted_scenario_resolves_run_relative_receipts(self, tmp_path, monkeypatch):
        import yaml as _yaml

        from asago_runner.adapters.artifacts import adapted_scenario
        from asago_runner.evidence import RunDir
        from asago_runner.replay import Eligibility

        run = RunDir.create(tmp_path / "run")
        handoff = run.path / "stages" / "scenario-generator" / "a" / "handoff"
        handoff.mkdir(parents=True)
        (handoff / "s.yaml").write_text(
            _yaml.safe_dump({"scenario_id": "s", "narrative": {"entry_point": "RAG retrieval"}})
        )
        (handoff / "s.feature").write_text("Feature: s\n")
        receipt = {
            "scenario_id": "s",
            "yaml": "stages/scenario-generator/a/handoff/s.yaml",
            "feature": "stages/scenario-generator/a/handoff/s.feature",
        }
        eligibility = Eligibility(
            scenario_id="s",
            eligible=True,
            surface="tool_return",
            reason="test",
            basis={},
            adaptation={"new_entry_point": "RAG retrieval (tool_execution)"},
        )
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)  # foreign CWD: must not resolve there
        dst = adapted_scenario(run, receipt, eligibility, run.path / "adapted")
        assert dst.is_file()
        assert (run.path / "adapted" / "s.feature").is_file()
        record = json.loads((run.path / "adapted" / "s.adaptation.json").read_text())
        # Parents are recorded run-relative, per the persisted-path contract.
        assert not record["canonical_yaml"].startswith("/")
        assert not record["adapted_yaml"].startswith("/")

    def test_replay_meta_paths_are_run_relative(self, tmp_path):
        from asago_runner.adapters.artifacts import write_replay_entries
        from asago_runner.config import RunConfig
        from asago_runner.evidence import RunDir
        from asago_runner.replay import Eligibility

        run = RunDir.create(tmp_path / "run")
        scenario = run.path / "handoff" / "s.yaml"
        scenario.parent.mkdir(parents=True)
        scenario.write_text("scenario_id: s\n")
        feature = run.path / "handoff" / "s.feature"
        feature.write_text("Feature: s\n")
        artifact_path = run.path / "artifacts" / "s-garak.json"
        artifact_path.parent.mkdir(parents=True)
        artifact = {
            "turns": [
                {"role": "system", "content": "You are an assistant.\n- refund(amount: float): Refund"},
                {"role": "user", "content": "attack"},
            ],
            "attack_turn_index": 1,
            "injection_surface": "user_turn",
            "detector_rubric": {
                "context": "ctx",
                "rubrics": {"attack_success": ["x"], "attack_blocked": ["y"]},
            },
        }
        artifact_path.write_text(json.dumps(artifact))
        from asago_runner.hashing import sha256_file

        cfg = RunConfig.load(_write_config(tmp_path, [POLICY_A]))
        candidate = {
            "scenario_id": "s",
            "gate": "full",
            "ok": True,
            "artifact_path": str(artifact_path),
            "artifact_sha256": sha256_file(artifact_path),
            "eligibility": Eligibility(
                scenario_id="s", eligible=True, surface="user_turn", reason="t", basis={}
            ),
            "receipt": {
                "scenario_id": "s",
                "yaml": "handoff/s.yaml",
                "feature": "handoff/s.feature",
            },
            "artifact": artifact,
        }
        written, gaps = write_replay_entries(run, run.path / "attempt", [candidate], cfg)
        assert gaps == []
        meta = json.loads((run.path / written[0]["meta_path"]).read_text())
        for path_value in (
            meta["parent_artifact"]["path"],
            meta["parent_scenario"]["scenario_yaml"]["path"],
            meta["parent_scenario"]["scenario_feature"]["path"],
        ):
            assert not str(path_value).startswith("/")
        # And no string in the persisted meta leaks the absolute run root.
        blob = json.dumps(meta)
        assert str(run.path) not in blob

    def test_duplicate_policy_basenames_rejected(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "p.md").write_text(POLICY_A)
        (tmp_path / "b").mkdir()
        (tmp_path / "b" / "p.md").write_text(POLICY_B)
        (tmp_path / "sys").mkdir()
        (tmp_path / "sys" / "u.md").write_text("# Use case\nA chat assistant.\n")
        (tmp_path / "m").mkdir()
        (tmp_path / "m" / "m.tsv").write_text(
            "subject_id\tsubject_source\tpredicate_id\tobject_id\tobject_source\tmapping_justification\n"
            "atlas-hallucination\tibm-risk-atlas\tskos:exactMatch\towasp-llm09\towasp-llm\tsemapv:ManualMappingCuration\n"
        )
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text(
            """schema_version: 1
run:
  label: dup
policy:
  documents:
    - path: a/p.md
    - path: b/p.md
system:
  use_case_file: sys/u.md
  identity:
    system_name: test
sssom:
  path: m/m.tsv
connections:
  mapper_llm: {base_url_env: A, model_env: B, api_key_env: C}
  scenario_llm: {base_url_env: A, model_env: B, api_key_env: C}
  artifact_llm: {base_url_env: A, model_env: B, api_key_env: C}
  target: {base_url_env: T, model_env: U, api_key_env: V}
  judge: {base_url_env: T, model_env: U, api_key_env: V}
"""
        )
        env = {k: "placeholder" for k in "ABCDEFGHIJKLMNOPQRSTUV"}
        code, out, _, err = _run(
            "new-run", "--config", str(cfg), "--run-dir",
            str(tmp_path / "run"), env_extra=env,
        )
        assert code != 0
        assert "rename one" in (err + json.dumps(out or {}))

    def test_counts_reconcile_with_featureless_admission(self, tmp_path):
        from asago_runner.evidence import RunDir
        from asago_runner.verify import _verify_counts

        run = RunDir.create(tmp_path / "run")
        (run.path / "reports").mkdir(exist_ok=True)
        (run.path / "reports" / "summary.json").write_text(
            json.dumps({"funnel": {"scenarios": {"admitted": 1}}})
        )
        admitted_hashes = {
            ("s1", "scenario_yaml"): "h1",
            ("s1", "scenario_feature"): "h2",
            ("s2", "scenario_yaml"): "h3",  # feature-less: excluded by both sides
        }
        checks = []
        _verify_counts(run, {}, admitted_hashes, lambda n, ok, d: checks.append((n, ok, d)))
        names = {n: ok for n, ok, _ in checks}
        assert names.get("counts.scenarios-reconcile") is True

    def test_missing_tools_schema_blocks_cleanly(self, tmp_path):
        cfg = _write_config(tmp_path, [POLICY_A])
        text = cfg.read_text().replace(
            "system:\n", "options:\n  tools_schema_file: nope/missing.json\nsystem:\n", 1
        )
        cfg.write_text(text)
        env = {k: "placeholder" for k in "ABCDEFGHIJKLMNOPQRSTUV"}
        code, out, _, err = _run(
            "new-run", "--config", str(cfg), "--run-dir",
            str(tmp_path / "run"), env_extra=env,
        )
        assert code != 0
        assert "tools_schema_file" in (err + json.dumps(out or {}))
        assert "Traceback" not in err


def test_relative_run_dir_records_absolute_original_paths(tmp_path):
    """A relative --run-dir must not leak CWD-relative paths into run.json.

    Regression for the 2026-11-14 addendum: originals_map values are later
    resolved against whatever CWD a command runs in, so they must be
    absolute.
    """
    import os

    cfg = _write_config(tmp_path, [POLICY_A])
    work = tmp_path / "work"
    work.mkdir()
    proc = subprocess.run(
        [str(RUNNER), "new-run", "--config", str(cfg), "--run-dir", "relrun"],
        cwd=work,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    run_dir = work / "relrun"
    manifest = json.loads((run_dir / "run.json").read_text())
    path_map = manifest["originals_map"]
    assert path_map
    for value in path_map.values():
        assert os.path.isabs(value), f"originals_map value is not absolute: {value!r}"
    # Load the copied config from a different CWD: every input must resolve.
    from asago_runner.config import RunConfig
    from asago_runner.evidence import RunDir

    run = RunDir(run_dir)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    old_cwd = os.getcwd()
    try:
        os.chdir(elsewhere)
        cfg_from_run = RunConfig.load(
            run.path / "originals" / "run-config.yaml",
            path_map=run.manifest().get("originals_map"),
        )
        assert cfg_from_run.policy_paths()
        for path in cfg_from_run.policy_paths():
            assert path.is_file(), path
    finally:
        os.chdir(old_cwd)


class TestWorkOwnershipLabels:
    """Users must always be able to tell whose work each step is."""

    def test_progress_steps_carry_owner_and_labels(self):
        from asago_runner.reporting import (
            derive_progress,
            render_progress_checklist,
        )

        manifest = {"run_id": "r", "subject": "built", "flow": {}, "stages": {}}
        progress = derive_progress(manifest)
        owners = {p["step"]: p["owner"] for p in progress}
        # Asago library work is labelled as such.
        for step in ("intake", "map", "scenarios", "artifacts"):
            assert owners[step] == "asago", step
        assert owners["evaluate"] == "external"
        for step in ("setup", "preflight", "report", "verify"):
            assert owners[step] == "runner", step
        for step in ("input-review", "conflict", "test-plan"):
            assert owners[step] == "review", step

        text = render_progress_checklist(progress, "r")
        assert "[ASAGO COMPONENT]" in text
        assert "[EXTERNAL: GARAK]" in text
        assert "[RUNNER]" in text
        assert "[YOUR REVIEW]" in text
        assert "the real Asago library, unmodified" in text

    def test_html_report_names_whose_work(self, tmp_path):
        from asago_runner.evidence import RunDir
        from asago_runner.reporting import build_summary, render_html

        run = RunDir.create(tmp_path / "run")

        def mutate(m):
            m["stages"] = {
                "policy-mapper": {"status": "completed", "latest_attempt": "a"},
                "garak": {"status": "completed", "latest_attempt": "b"},
            }

        run.update_manifest(mutate)
        summary = build_summary(run)
        render_html(run, summary)
        html = (run.path / "reports" / "index.html").read_text()
        assert "[ASAGO COMPONENT]" in html
        assert "[EXTERNAL: GARAK]" in html
        assert "Policy Mapper" in html and "Garak Evaluation" in html
        assert "Whose work" in html


class TestConflictStepStates:
    """Parsing is the component's; the conflict decision is the user's."""

    def _states(self, flow):
        from asago_runner.reporting import derive_progress

        progress = derive_progress({"run_id": "r", "subject": "built", "flow": flow, "stages": {}})
        return {p["step"]: p["state"] for p in progress}

    def test_single_document_conflict_not_needed(self):
        states = self._states({"effective_inputs": {"mode": "originals"}})
        assert states["conflict"] == "not_applicable"

    def test_multi_document_conflict_pending(self):
        states = self._states({"conflict_review": {"state": "pending"}})
        assert states["intake"] == "done"  # parsing finished
        assert states["conflict"] == "needs_review"

    def test_multi_document_conflict_resolved(self):
        states = self._states(
            {"conflict_review": {"state": "resolved"}, "effective_inputs": {"mode": "reconciled"}}
        )
        assert states["conflict"] == "done"

    def test_render_shows_not_applicable_reason(self):
        from asago_runner.reporting import derive_progress, render_progress_checklist

        progress = derive_progress(
            {"run_id": "r", "subject": "built", "flow": {"effective_inputs": {}}, "stages": {}}
        )
        text = render_progress_checklist(progress, "r")
        assert "not needed: single policy document" in text


class TestCanonicalPlan:
    """The welcome plan is deterministic runner output, not agent prose."""

    def test_plan_is_deterministic_and_complete(self):
        from asago_runner.reporting import render_plan

        first = render_plan("built")
        assert first == render_plan("built")  # identical every time
        # Every user-facing step is numbered and owner-tagged in order.
        for marker in (
            "[RUNNER] Check the environment",
            "[YOUR REVIEW] Input readiness",
            "[ASAGO COMPONENT] Parse your policies",
            "[YOUR REVIEW] Policy conflicts",
            "[ASAGO COMPONENT] Policy Mapper",
            "[ASAGO COMPONENT] Scenario Generator",
            "[ASAGO COMPONENT] Artifact Generator",
            "[YOUR REVIEW] Test plan",
            "[EXTERNAL: GARAK] Evaluate",
            "[RUNNER] Report and verify",
        ):
            assert marker in first, marker
        assert "Two steps always need decisions from you (2 and 8)" in first
        assert "step 4 only when several policies disagree" in first
        assert "🧩 [ASAGO COMPONENT] = the real Asago library" in first

    def test_proposed_plan_stops_after_scenarios(self):
        from asago_runner.reporting import render_plan

        proposed = render_plan("proposed")
        assert "[ASAGO COMPONENT] Scenario Generator" in proposed
        assert "[ASAGO COMPONENT] Artifact Generator" not in proposed
        assert "[EXTERNAL: GARAK]" not in proposed
        assert "deliberately stop after the scenarios" in proposed
        assert "One step always needs a decision from you (2)" in proposed

    def test_plan_rejects_unknown_subject(self):
        from asago_runner.reporting import render_plan

        with pytest.raises(ValueError):
            render_plan("maybe")

    def test_plan_command_prints_and_exits_zero(self):
        proc = subprocess.run(
            [str(RUNNER), "plan", "--subject", "proposed"],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0
        assert proc.stdout.startswith("Welcome to Asago.")
        assert "[ASAGO COMPONENT] Policy Mapper" in proc.stdout


class TestReviewRegressionFixes:
    def test_blocked_intake_is_not_shown_as_done(self, tmp_path):
        cfg = _write_config(tmp_path, [""])
        env = {k: "placeholder" for k in "ABCDEFGHIJKLMNOPQRSTUV"}
        run_dir = tmp_path / "empty-run"
        _run("new-run", "--config", str(cfg), "--run-dir", str(run_dir), env_extra=env)
        code, _, _, _ = _run("intake", str(run_dir), env_extra=env)
        assert code == 3
        code, payload, _, _ = _run("status", str(run_dir), env_extra=env)
        assert code == 0
        states = {item["step"]: item["state"] for item in payload["progress"]}
        assert states["intake"] == "blocked"

    def test_report_conversation_must_exist_and_stay_in_run(self, tmp_path):
        cfg = _write_config(tmp_path, ["# Policy\n\nData must be protected."])
        env = {k: "placeholder" for k in "ABCDEFGHIJKLMNOPQRSTUV"}
        run_dir = tmp_path / "conv-run"
        _run("new-run", "--config", str(cfg), "--run-dir", str(run_dir), env_extra=env)
        _run("intake", str(run_dir), env_extra=env)

        code, payload, _, _ = _run(
            "report", str(run_dir), "--conversation", "reports/missing.md", env_extra=env
        )
        assert code == 1 and "not found" in payload["error"]

        outside = tmp_path / "outside.md"
        outside.write_text("SESSION-MARKER")
        code, payload, _, _ = _run(
            "report", str(run_dir), "--conversation", str(outside), env_extra=env
        )
        assert code == 1 and "inside the run directory" in payload["error"]

        (run_dir / "reports").mkdir(exist_ok=True)
        (run_dir / "reports" / "conv.md").write_text("# Session\n\nSESSION-MARKER")
        code, payload, _, _ = _run(
            "report", str(run_dir), "--conversation", "reports/conv.md", env_extra=env
        )
        assert code == 0 and payload["conversation_included"] is True
        html = (run_dir / "reports" / "index.html").read_text()
        summary = (run_dir / "reports" / "summary.json").read_text()
        assert "SESSION-MARKER" in html
        assert "SESSION-MARKER" not in summary

    def test_verify_resolves_legacy_absolute_paths_inside_moved_run(self, tmp_path):
        from asago_runner.verify import _resolve

        run = RunDir.create(tmp_path / "moved")
        target = run.path / "stages" / "artifact-generator" / "0001-a" / "entry.json"
        target.parent.mkdir(parents=True)
        target.write_text("{}")
        legacy = "/old/location/runs/live/stages/artifact-generator/0001-a/entry.json"
        assert _resolve(run, legacy) == target

    def test_report_uses_the_runs_custom_sssom(self, tmp_path):
        from asago_runner.report_page import _sssom_path, collect_report_data

        run = RunDir.create(tmp_path / "custom-sssom")
        sssom = run.path / "originals" / "sssom" / "custom.tsv"
        sssom.parent.mkdir(parents=True)
        sssom.write_text(
            "subject_id\tsubject_source\tpredicate_id\tobject_id\tobject_source\t"
            "mapping_justification\n"
            "atlas-custom\tibm-risk-atlas\tskos:exactMatch\tnist-data-privacy\t"
            "nist-ai-rmf\texample\n"
        )
        attempt = run.path / "stages" / "policy-mapper" / "0001-x"
        attempt.mkdir(parents=True)
        (attempt / "risk-extraction.json").write_text(
            json.dumps(
                {"risks": [{"risk_id": "atlas-custom", "risk_name": "Custom",
                            "taxonomy": "ibm-risk-atlas",
                            "grounding_confidence": "high", "evidence": []}]}
            )
        )
        run.update_manifest(
            lambda m: m.update(
                {
                    "subject": "built",
                    "stages": {"policy-mapper": {"status": "completed",
                        "attempts": [{"attempt_id": "0001-x", "status": "completed"}]}},
                    "flow": {"mapper_output": {
                        "extraction": "stages/policy-mapper/0001-x/risk-extraction.json"}},
                    "config_snapshot": {"raw_non_secret": {
                        "sssom": {"path": "mappings/custom.tsv"}}},
                    "originals_map": {
                        "mappings/custom.tsv": "originals/sssom/custom.tsv"},
                }
            )
        )
        assert _sssom_path(run) == sssom
        details = collect_report_data(run, {})
        mapping = details["policy"]["theme_mapping"]
        assert details["policy"]["counts"]["themes"] == {"privacy": 1}
        assert mapping["sssom"] == "originals/sssom/custom.tsv"
        assert mapping["sssom_location"] == "run"

    def test_report_warns_raw_content_and_keeps_it_out_of_summary(self, tmp_path):
        from asago_runner.reporting import build_summary, render_html

        run = RunDir.create(tmp_path / "sensitive")
        attempt = run.path / "stages" / "policy-mapper" / "0001-x"
        attempt.mkdir(parents=True)
        (attempt / "risk-extraction.json").write_text(
            json.dumps({"risks": [{
                "risk_id": "atlas-example", "risk_name": "Example",
                "taxonomy": "ibm-risk-atlas", "grounding_confidence": "high",
                "evidence": [{"text": "SECRET-POLICY-QUOTE", "document": "/p.pdf"}],
            }]})
        )
        run.update_manifest(lambda m: m.update({
            "subject": "built",
            "stages": {"policy-mapper": {"status": "completed",
                "attempts": [{"attempt_id": "0001-x", "status": "completed"}]}},
            "flow": {"mapper_output": {
                "extraction": "stages/policy-mapper/0001-x/risk-extraction.json"}},
        }))
        summary = build_summary(run)
        render_html(run, summary)
        html = (run.path / "reports" / "index.html").read_text()
        summary_text = (run.path / "reports" / "summary.json").read_text()
        assert "This report contains raw material." in html
        assert "SECRET-POLICY-QUOTE" in html
        assert "SECRET-POLICY-QUOTE" not in summary_text

    def test_watch_follow_exits_on_needs_review(self, tmp_path):
        run = RunDir.create(tmp_path / "review-watch")
        run.path.joinpath("stages", "scenario-generator", "0001-r").mkdir(parents=True)
        run.update_manifest(lambda m: m.setdefault("stages", {}).update({
            "scenario-generator": {
                "status": "needs_review", "latest_attempt": "0001-r",
                "attempts": [{"attempt_id": "0001-r", "status": "needs_review"}],
            }
        }))
        code, payload, stdout, _ = _run(
            "watch", str(run.path), "--stage", "scenarios", "--follow",
            "--interval", "1", "--timeout", "20",
        )
        assert code == 2
        assert "needs_review" in stdout
        assert payload["health"] == "needs_review"


class TestOptionalStageDeadline:
    def _cfg(self, tmp_path, scope_line):
        cfg = _write_config(tmp_path, ["# Policy\n\nData must be protected."])
        text = cfg.read_text()
        cfg.write_text(text + ("\nscope:\n" + scope_line if scope_line else ""))
        return cfg

    def test_absent_and_null_mean_no_deadline(self, tmp_path):
        from asago_runner.config import RunConfig

        assert RunConfig.load(self._cfg(tmp_path, "")).stage_deadline_seconds is None
        assert (
            RunConfig.load(
                self._cfg(tmp_path, "  stage_deadline_seconds: null\n")
            ).stage_deadline_seconds
            is None
        )
        assert (
            RunConfig.load(
                self._cfg(tmp_path, "  stage_deadline_seconds: 0\n")
            ).stage_deadline_seconds
            is None
        )

    def test_explicit_number_is_kept(self, tmp_path):
        from asago_runner.config import RunConfig

        cfg = RunConfig.load(
            self._cfg(tmp_path, "  stage_deadline_seconds: 900\n")
        )
        assert cfg.stage_deadline_seconds == 900

    def test_negative_or_text_is_rejected(self, tmp_path):
        from asago_runner.config import ConfigError, RunConfig

        for value in ("-5", "'soon'"):
            with pytest.raises(ConfigError, match="stage_deadline_seconds"):
                RunConfig.load(
                    self._cfg(tmp_path, f"  stage_deadline_seconds: {value}\n")
                )


class TestMapperConcurrencyReview:
    def test_preflight_request_shows_the_throttle(self, tmp_path):
        cfg = _write_config(tmp_path, ["# Policy\n\nData must be protected."])
        cfg.write_text(
            cfg.read_text() + "\noptions:\n  mapper_max_concurrent: 4\n"
        )
        env = {k: "placeholder" for k in "ABCDEFGHIJKLMNOPQRSTUV"}
        run_dir = tmp_path / "throttle-run"
        code, _, _, _ = _run(
            "new-run", "--config", str(cfg), "--run-dir", str(run_dir), env_extra=env
        )
        assert code == 0
        code, _, _, _ = _run("preflight", str(run_dir), env_extra=env)
        assert code == 2
        request = json.loads(
            (run_dir / "reviews" / "input-readiness.request.json").read_text()
        )
        assert request["summary"]["options"]["mapper_max_concurrent"] == 4
        assert request["summary"]["scope"]["stage_deadline_seconds"] is None
