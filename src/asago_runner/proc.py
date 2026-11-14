"""Isolated subprocess execution for component stages.

Every component runs as a subprocess with:
- an explicit argument array (no shell);
- a clean, runner-controlled working directory;
- a per-stage environment *allowlist* (platform basics plus exactly the
  variables the stage needs) so unrelated provider keys, stray ``.env``
  settings and ambient configuration cannot leak in or reroute a role;
- a parent-enforced wall-clock deadline with bounded termination grace and
  process-group cleanup.

Secrets given to a child appear only in its environment; captured output is
redacted against those secret values before it is written to evidence.
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from .evidence import atomic_write_json, utc_now_iso

# Platform basics every child needs. Deliberate, recorded, not secrets.
_BASE_ENV_ALLOWLIST = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_DIR",
    "NO_PROXY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    # macOS framework interop
    "__CF_USER_TEXT_ENCODING",
    # Local model caches stay local; documented in the data-flow table.
    "HF_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
    # OpenTelemetry settings are honoured for the runner's own export only
    # when the runner itself exports; children do not export telemetry.
)

TERMINATION_GRACE_SECONDS = 10.0


@dataclass
class ProcResult:
    command: list[str]
    cwd: str
    deadline_seconds: float
    returncode: int | None
    timed_out: bool
    started_at: str
    ended_at: str
    duration_seconds: float
    stdout_path: str
    stderr_path: str
    termination_reason: str | None = None
    env_names: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def child_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build the child environment: allowlisted base plus explicit extras."""
    env: dict[str, str] = {}
    for name in _BASE_ENV_ALLOWLIST:
        value = os.environ.get(name)
        if value is not None:
            env[name] = value
    for name, value in (extra or {}).items():
        env[name] = value
    return env


_SECRET_NAME_RE = None


def _secret_values(env_extra: Mapping[str, str]) -> dict[str, str]:
    """Only values whose variable name looks like a credential.

    Model names, base URLs and other non-secret settings stay readable in
    captured output for identity context; keys, tokens and passwords do
    not.
    """
    global _SECRET_NAME_RE
    if _SECRET_NAME_RE is None:
        import re

        _SECRET_NAME_RE = re.compile(r"(key|token|secret|password|auth)", re.I)
    return {
        name: value
        for name, value in env_extra.items()
        if _SECRET_NAME_RE.search(name) and value
    }


def redact_secrets(text: str, secrets: Mapping[str, str]) -> str:
    """Replace known secret values in captured output."""
    for value in secrets.values():
        if value and len(value) >= 8:
            text = text.replace(value, "<redacted>")
    return text


def run_subprocess(
    argv: list[str],
    *,
    cwd: str | Path,
    deadline_seconds: float,
    env_extra: Mapping[str, str] | None = None,
    stdout_path: str | Path,
    stderr_path: str | Path,
    dispatch_record_path: str | Path | None = None,
) -> ProcResult:
    """Run one component subprocess under a wall-clock deadline.

    ``dispatch_record_path`` is written *before* the process starts so a crash
    cannot erase the existence of a dispatch.
    """
    argv = [str(a) for a in argv]
    cwd = Path(cwd)
    cwd.mkdir(parents=True, exist_ok=True)
    env = child_env(env_extra)
    started_at = utc_now_iso()
    start_mono = time.monotonic()

    if dispatch_record_path is not None:
        atomic_write_json(
            dispatch_record_path,
            {
                "command": argv,
                "cwd": str(cwd),
                "started_at": started_at,
                "deadline_seconds": deadline_seconds,
                "env_names": sorted(env.keys()),
                "status": "dispatched",
            },
        )

    stdout_handle = open(stdout_path, "w", encoding="utf-8")
    stderr_handle = open(stderr_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        argv,
        cwd=str(cwd),
        env=env,
        stdout=stdout_handle,
        stderr=stderr_handle,
        start_new_session=True,  # own process group for group cleanup
    )
    if dispatch_record_path is not None:
        import json

        record_path = Path(dispatch_record_path)
        if record_path.is_file():
            record = json.loads(record_path.read_text(encoding="utf-8"))
            record["pid"] = proc.pid
            record["status"] = "running"
            atomic_write_json(record_path, record)
    timed_out = False
    termination_reason: str | None = None
    try:
        while True:
            try:
                proc.wait(timeout=1.0)
                break
            except subprocess.TimeoutExpired:
                elapsed = time.monotonic() - start_mono
                if elapsed >= deadline_seconds:
                    timed_out = True
                    termination_reason = "deadline-exceeded"
                    _terminate_group(proc)
                    try:
                        proc.wait(timeout=TERMINATION_GRACE_SECONDS)
                    except subprocess.TimeoutExpired:
                        _kill_group(proc)
                        proc.wait()
                    break
    finally:
        stdout_handle.close()
        stderr_handle.close()
        # Redact secret values from captured output before it becomes evidence.
        secrets = _secret_values(env_extra or {})
        if secrets:
            for path in (stdout_path, stderr_path):
                target = Path(path)
                if target.is_file():
                    text = target.read_text(encoding="utf-8", errors="replace")
                    redacted = redact_secrets(text, secrets)
                    if redacted != text:
                        target.write_text(redacted, encoding="utf-8")

    ended_at = utc_now_iso()
    duration = time.monotonic() - start_mono
    result = ProcResult(
        command=argv,
        cwd=str(cwd),
        deadline_seconds=deadline_seconds,
        returncode=proc.returncode,
        timed_out=timed_out,
        started_at=started_at,
        ended_at=ended_at,
        duration_seconds=round(duration, 3),
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        termination_reason=termination_reason,
        env_names=sorted(env.keys()),
    )
    if dispatch_record_path is not None:
        record_path = Path(dispatch_record_path)
        if record_path.is_file():
            import json

            record = json.loads(record_path.read_text(encoding="utf-8"))
            record.update(
                {
                    "status": "timeout" if timed_out else "exited",
                    "returncode": proc.returncode,
                    "ended_at": ended_at,
                    "duration_seconds": round(duration, 3),
                    "termination_reason": termination_reason,
                }
            )
            atomic_write_json(record_path, record)
    return result


def _terminate_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        proc.terminate()


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()


def quote_command(argv: list[str]) -> str:
    return " ".join(shlex.quote(str(a)) for a in argv)
