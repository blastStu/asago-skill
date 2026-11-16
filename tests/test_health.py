"""Deterministic stage-health classification and error extraction."""

from __future__ import annotations

import json
import os
import time

import pytest

from asago_runner.evidence import RunDir
from asago_runner.health import (
    extract_error_summary,
    render_health,
    summarize_attempt,
)

FAILED_LOG = """
[10:00] INFO pipeline: Grounding chunk 6/7 pass 3/3: 5 risks grounded
[10:01] INFO openai._base_client: Retrying request in 0.766555 seconds (retry 2 of 2)
[10:02] INFO openai._base_client: Retrying request in 0.401866 seconds (retry 1 of 2)
Traceback (most recent call last):
  File "pipeline.py", line 548, in _ground_group_multi
  File "client.py", line 1218, in _request
openai.APIConnectionError: Connection error.
"""


class TestErrorSummary:
    def test_extracts_final_traceback_line(self):
        assert (
            extract_error_summary(FAILED_LOG)
            == "openai.APIConnectionError: Connection error."
        )

    def test_falls_back_to_exception_line_without_traceback(self):
        assert extract_error_summary("ValueError: missing input\n") == (
            "ValueError: missing input"
        )

    def test_clean_log_has_no_error(self):
        assert extract_error_summary("chunk 1 grounded\nchunk 2 grounded\n") is None


def _attempt(run: RunDir, *, pid: int, log: str, status: str | None = None,
             age_seconds: float = 0.0) -> str:
    attempt = run.path / "stages" / "policy-mapper" / "0001-test"
    attempt.mkdir(parents=True, exist_ok=True)
    (attempt / "stderr.log").write_text(log)
    (attempt / "dispatch.json").write_text(
        json.dumps(
            {
                "status": "running" if status is None else "exited",
                "pid": pid,
                "started_at": "2026-11-14T10:00:00+00:00",
            }
        )
    )
    if age_seconds:
        past = time.time() - age_seconds
        os.utime(attempt / "stderr.log", (past, past))
    if status is not None:
        run.update_manifest(
            lambda m: m.setdefault("stages", {}).setdefault("policy-mapper", {}).update(
                {
                    "status": status,
                    "latest_attempt": "0001-test",
                    "attempts": [{"attempt_id": "0001-test", "status": status}],
                }
            )
        )
    return "0001-test"


class TestClassification:
    def test_failed_attempt_reports_cause(self, tmp_path):
        run = RunDir.create(tmp_path / "run")
        _attempt(run, pid=999999, log=FAILED_LOG, status="failed")
        summary = summarize_attempt(run, "map")
        assert summary["health"] == "failed"
        assert summary["last_error"] == "openai.APIConnectionError: Connection error."
        assert summary["retry_count"] == 2
        assert "APIConnectionError" in summary["hint"]

    def test_running_with_recent_retries_is_retrying(self, tmp_path):
        run = RunDir.create(tmp_path / "run")
        _attempt(run, pid=os.getpid(), log=FAILED_LOG)
        summary = summarize_attempt(run, "map")
        assert summary["health"] == "retrying"
        assert summary["running"] is True

    def test_silent_alive_process_is_stalled(self, tmp_path):
        run = RunDir.create(tmp_path / "run")
        _attempt(run, pid=os.getpid(), log="chunk 1 grounded\n", age_seconds=900)
        summary = summarize_attempt(run, "map", stall_seconds=300)
        assert summary["health"] == "stalled"
        assert "No log activity" in summary["hint"]

    def test_healthy_progress_is_running(self, tmp_path):
        run = RunDir.create(tmp_path / "run")
        _attempt(run, pid=os.getpid(), log="[10:00] Grounding chunk 6/7 pass 3/3\n")
        summary = summarize_attempt(run, "map")
        assert summary["health"] == "running"
        assert "chunk 6/7" in summary["last_milestone"]

    def test_completed_stage_is_done(self, tmp_path):
        run = RunDir.create(tmp_path / "run")
        _attempt(run, pid=999999, log="chunk done\n", status="completed")
        assert summarize_attempt(run, "map")["health"] == "done"

    def test_no_attempt_yet(self, tmp_path):
        run = RunDir.create(tmp_path / "run")
        assert summarize_attempt(run, "map")["health"] == "no-attempt"

    def test_render_is_one_line(self, tmp_path):
        run = RunDir.create(tmp_path / "run")
        _attempt(run, pid=999999, log=FAILED_LOG, status="failed")
        rendered = render_health(summarize_attempt(run, "map"))
        assert "\n" not in rendered
        assert rendered.startswith("🔴 [asago-runner] policy-mapper: failed")
        assert "APIConnectionError" in rendered


class TestWatchCommand:
    def test_watch_json_reports_failure(self, tmp_path):
        import subprocess
        from pathlib import Path

        runner = str(Path(__file__).resolve().parents[1] / ".venv" / "bin" / "asago-runner")
        run = RunDir.create(tmp_path / "run")
        _attempt(run, pid=999999, log=FAILED_LOG, status="failed")
        proc = subprocess.run(
            [runner, "watch", str(run.path), "--stage", "map", "--json"],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0
        payload = json.loads(proc.stdout.strip().splitlines()[-1])
        assert payload["health"] == "failed"
        assert "APIConnectionError" in payload["last_error"]


class TestScenarioFailureParsing:
    """Projection-readiness aborts and filter failures are classified."""

    READINESS = (
        "Pipeline failed: Projection readiness failed before projection: "
        "missing resource categories external_integrations, trust_boundaries; "
        "supply a reviewed architecture with '--profile'."
    )

    FILTER = (
        "WARNING Filter call failed for seed AP-T10-01 (attempt 1):\n"
        "ERROR   Filter protocol failure for seed AP-T10-01 after retry\n"
        "ERROR   Filter protocol failure for seed AP-T15-01 after retry\n"
    )

    def test_readiness_failure_categories(self):
        from asago_runner.adapters.scenarios import parse_readiness_failure

        assert parse_readiness_failure(self.READINESS) == [
            "external_integrations",
            "trust_boundaries",
        ]

    def test_readiness_failure_absent_in_normal_log(self):
        from asago_runner.adapters.scenarios import parse_readiness_failure

        assert parse_readiness_failure("chunk 3/13 grounded\n") is None

    def test_filter_failures_are_listed_once(self):
        from asago_runner.adapters.scenarios import parse_filter_failures

        assert parse_filter_failures(self.FILTER) == ["AP-T10-01", "AP-T15-01"]

    def test_profile_required_request_is_durable_and_actionable(self, tmp_path):
        from asago_runner.adapters.scenarios import (
            write_profile_required_request,
        )

        run = RunDir.create(tmp_path / "run")
        path = write_profile_required_request(
            run, "0001-ac0ece", ["external_integrations", "trust_boundaries"]
        )
        assert path.is_file()
        payload = json.loads(path.read_text())
        assert payload["kind"] == "profile-required"
        assert payload["missing_resource_categories"] == [
            "external_integrations",
            "trust_boundaries",
        ]
        assert "system.profile_file" in payload["how_to"]
        assert "not reused" in payload["how_to"]


class TestGarakAndReviewHealth:
    def test_garak_child_dispatch_logs_are_read(self, tmp_path):
        run = RunDir.create(tmp_path / "garak")
        child = run.path / "stages" / "garak" / "0001-x" / "scenario-a"
        child.mkdir(parents=True)
        (child / "stderr.log").write_text(FAILED_LOG)
        (child / "dispatch.json").write_text(
            json.dumps(
                {
                    "pid": 999999,
                    "status": "exited",
                    "started_at": "2026-11-14T10:00:00+00:00",
                }
            )
        )
        run.update_manifest(
            lambda m: m.setdefault("stages", {}).setdefault("garak", {}).update(
                {
                    "status": "failed",
                    "latest_attempt": "0001-x",
                    "attempts": [{"attempt_id": "0001-x", "status": "failed"}],
                }
            )
        )
        summary = summarize_attempt(run, "evaluate")
        assert summary["line_count"] > 0
        assert summary["health"] == "failed"
        assert summary["last_error"] == "openai.APIConnectionError: Connection error."

    def test_garak_alive_child_with_retries_is_retrying(self, tmp_path):
        run = RunDir.create(tmp_path / "garak2")
        child = run.path / "stages" / "garak" / "0001-y" / "scenario-b"
        child.mkdir(parents=True)
        (child / "stderr.log").write_text(
            "chunk grounded\nRetrying request in 0.7 seconds (retry 2 of 2)\n"
        )
        (child / "dispatch.json").write_text(
            json.dumps({"pid": os.getpid(), "status": "running"})
        )
        summary = summarize_attempt(run, "evaluate")
        assert summary["running"] is True
        assert summary["health"] == "retrying"

    def test_needs_review_is_terminal_health(self, tmp_path):
        run = RunDir.create(tmp_path / "review")
        attempt = run.path / "stages" / "scenario-generator" / "0001-r"
        attempt.mkdir(parents=True)
        (attempt / "stderr.log").write_text("projection readiness failed\n")
        run.update_manifest(
            lambda m: m.setdefault("stages", {}).setdefault(
                "scenario-generator", {}
            ).update(
                {
                    "status": "needs_review",
                    "latest_attempt": "0001-r",
                    "attempts": [{"attempt_id": "0001-r", "status": "needs_review"}],
                }
            )
        )
        summary = summarize_attempt(run, "scenarios")
        assert summary["health"] == "needs_review"
