"""Evidence tree, decision journal, locking, inventory and subprocess tests."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from asago_runner.evidence import RunDir, RunLockError
from asago_runner.hashing import sha256_file
from asago_runner.proc import child_env, redact_secrets, run_subprocess


@pytest.fixture()
def run(tmp_path) -> RunDir:
    return RunDir.create(tmp_path / "run")


class TestRunDir:
    def test_create_layout(self, run: RunDir):
        for sub in ("originals", "derived", "reviews", "preflight", "reports",
                    "stages/policy-mapper", "stages/garak"):
            assert (run.path / sub).is_dir()

    def test_attempt_dirs_increment(self, run: RunDir):
        id1, dir1 = run.new_attempt_dir("policy-mapper")
        id2, dir2 = run.new_attempt_dir("policy-mapper")
        assert dir1 != dir2 and dir1.is_dir() and dir2.is_dir()

    def test_stage_attempt_records_survive_outcome(self, run: RunDir):
        attempt_id, _ = run.new_attempt_dir("garak")
        run.record_stage_attempt("garak", attempt_id, {"started_at": "t"})
        run.record_stage_outcome("garak", attempt_id, {"status": "failed"})
        stages = run.manifest()["stages"]["garak"]
        assert stages["status"] == "failed"
        assert len(stages["attempts"]) == 1

    def test_lock_excludes_second_writer(self, run: RunDir):
        with run.locked("first"):
            with pytest.raises(RunLockError):
                run.acquire_lock("second")
        with run.locked("again"):
            pass  # released properly

    def test_lock_released_on_exception(self, run: RunDir):
        with pytest.raises(RuntimeError):
            with run.locked("holder"):
                raise RuntimeError("boom")
        with run.locked("next"):
            pass

    def test_decisions_append_only(self, run: RunDir):
        first = run.append_decision({"category": "test", "state": "resolved"})
        second = run.append_decision({"category": "test", "state": "resolved",
                                      "supersedes": first})
        records = run.decisions()
        assert len(records) == 2  # correction appends; never rewrites
        assert run.resolved_decision("test")["id"] == second

    def test_inventory_hashes_payload(self, run: RunDir):
        target = run.path / "originals" / "doc.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("content")
        inventory = run.rebuild_inventory()
        entry = next(e for e in inventory["files"] if e["path"] == "originals/doc.md")
        assert entry["sha256"] == sha256_file(target)
        # inventory.json itself is excluded (no self-referential checksum)
        assert not any(e["path"] == "inventory.json" for e in inventory["files"])


class TestSubprocess:
    def test_env_allowlist_excludes_stray_keys(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "stray-gemini-key")
        monkeypatch.setenv("OPENROUTER_API_KEY", "stray-or-key")
        monkeypatch.setenv("SECRET_TOKEN", "stray-token")
        proc = run_subprocess(
            [sys.executable, "-c",
             "import os,json;print(json.dumps(sorted(k for k in os.environ"
             " if 'KEY' in k or 'TOKEN' in k)))"],
            cwd=tmp_path, deadline_seconds=30,
            env_extra={"MY_STAGE_KEY": "stage-value"},
            stdout_path=tmp_path / "out.log", stderr_path=tmp_path / "err.log",
        )
        seen = json.loads(Path(proc.stdout_path).read_text().strip().splitlines()[-1])
        assert "GEMINI_API_KEY" not in seen
        assert "OPENROUTER_API_KEY" not in seen
        assert "SECRET_TOKEN" not in seen
        assert "MY_STAGE_KEY" in seen

    def test_deadline_kills_process_group(self, tmp_path):
        start = time.monotonic()
        proc = run_subprocess(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            cwd=tmp_path, deadline_seconds=2,
            env_extra=None,
            stdout_path=tmp_path / "out.log", stderr_path=tmp_path / "err.log",
        )
        assert proc.timed_out
        assert proc.termination_reason == "deadline-exceeded"
        assert time.monotonic() - start < 20

    def test_secret_redaction_in_captured_output(self, tmp_path):
        proc = run_subprocess(
            [sys.executable, "-c", "print('the key is sk-secret-abcdef123456')"],
            cwd=tmp_path, deadline_seconds=30,
            env_extra={"MY_API_KEY": "sk-secret-abcdef123456"},
            stdout_path=tmp_path / "out.log", stderr_path=tmp_path / "err.log",
        )
        text = Path(proc.stdout_path).read_text()
        assert "sk-secret-abcdef123456" not in text
        assert "<redacted>" in text

    def test_dispatch_record_written_before_process(self, tmp_path):
        record = tmp_path / "dispatch.json"
        proc = run_subprocess(
            [sys.executable, "-c", "raise SystemExit(3)"],
            cwd=tmp_path, deadline_seconds=30, env_extra=None,
            stdout_path=tmp_path / "out.log", stderr_path=tmp_path / "err.log",
            dispatch_record_path=record,
        )
        data = json.loads(record.read_text())
        assert data["status"] == "exited"
        assert data["returncode"] == 3

    def test_redact_secrets_helper(self):
        assert redact_secrets("a KEYVALUE b", {"K": "KEYVALUE"}) == "a <redacted> b"
