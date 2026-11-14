"""Deterministic health and progress summaries for running stages.

A long component stage writes a noisy log. Rather than leave an agent to
invent greps (and miss a retry storm or a connection drop), the runner
classifies the attempt itself:

- is the process still alive?
- how long since the log last moved (a silent stall)?
- how many retries and errors are in the log, and what was the last error?
- what was the last meaningful milestone?

The classification is heuristic but stable: the same log produces the same
answer. It supplements — never replaces — the retained log and the stage's
final outcome.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

from .evidence import RunDir

_STAGE_ALIASES = {
    "map": "policy-mapper",
    "scenarios": "scenario-generator",
    "artifacts": "artifact-generator",
    "evaluate": "garak",
}

# Lines that are progress milestones rather than noise.
_MILESTONE_RE = re.compile(
    r"chunk|grounded|mapped|filtered|collapsed|index|writing|written|"
    r"complete|quarantin|candidate|scenario|artifact|attempt|pass \d",
    re.I,
)
# Lines that indicate a problem worth surfacing immediately.
_ERROR_RE = re.compile(r"\b(error|exception|traceback|failed|refused|timeout)\b", re.I)
_RETRY_RE = re.compile(r"retrying request|backoff|retry \d", re.I)
# Log noise that is never a milestone or an error.
_NOISE_RE = re.compile(
    r"httpx|httpcore|docling|Fetching|Downloading|Loading plugin|Registered |"
    r"Initializing|resource_tracker|UserWarning|warnings\.warn",
    re.I,
)
# A bare exception line, e.g. "APIConnectionError: Connection error."
_EXC_LINE_RE = re.compile(r"^([A-Za-z_][\w.]*(?:Error|Exception))(?::\s*(.*))?$")


def _pid_alive(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def attempt_logs(attempt_dir: Path) -> list[Path]:
    """The log files worth summarising for an attempt.

    Most stages write ``stderr.log`` at the attempt root. Garak writes one
    directory per dispatched artifact (``<scenario>-<id>/``) with its own
    ``stderr.log``, so those child logs are included too. Sorted oldest to
    newest so the newest failure is the last thing the error extractor sees.
    """
    paths: list[Path] = []
    stderr = attempt_dir / "stderr.log"
    if stderr.is_file():
        paths.append(stderr)
    for child in sorted(attempt_dir.iterdir()):
        if child.is_dir():
            child_stderr = child / "stderr.log"
            if child_stderr.is_file():
                paths.append(child_stderr)
    for pipeline_log in sorted((attempt_dir / "runs").rglob("pipeline.log")):
        paths.append(pipeline_log)
    paths.sort(key=lambda path: path.stat().st_mtime)
    return paths


def extract_error_summary(text: str) -> str | None:
    """The most useful failure line from a log, or None.

    Prefers the final line of the last traceback (the exception class and
    message); falls back to the last line that looks like an exception.
    """
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    last_traceback = None
    for index, line in enumerate(lines):
        if line.startswith("Traceback (most recent call last)"):
            last_traceback = index
    if last_traceback is not None:
        for line in reversed(lines[last_traceback + 1 :]):
            stripped = line.strip()
            if _EXC_LINE_RE.match(stripped):
                return stripped[:400]
    for line in reversed(lines):
        stripped = line.strip()
        if _EXC_LINE_RE.match(stripped):
            return stripped[:400]
    return None


def summarize_attempt(
    run: RunDir,
    stage: str | None = None,
    *,
    stall_seconds: float = 300.0,
) -> dict[str, Any]:
    """Classify one stage attempt's health deterministically."""
    stage_name = _STAGE_ALIASES.get(stage, stage) if stage else None
    stages_root = run.path / "stages"
    stage_dirs = [d for d in stages_root.iterdir() if d.is_dir()] if stages_root.is_dir() else []
    if stage_name:
        stage_dirs = [d for d in stage_dirs if d.name == stage_name]
    attempts = [a for d in stage_dirs for a in d.iterdir() if a.is_dir()]
    if not attempts:
        return {
            "stage": stage_name,
            "attempt": None,
            "health": "no-attempt",
            "detail": "no stage attempts recorded yet",
        }
    attempt_dir = max(attempts, key=lambda a: a.stat().st_mtime)
    stage_name = attempt_dir.parent.name

    logs = attempt_logs(attempt_dir)
    text = ""
    # Log silence is measured from the LOG files only: the attempt
    # directory is touched by dispatch/outcome writes and would mask a
    # stalled child.
    newest_mtime = max((p.stat().st_mtime for p in logs), default=None)
    for path in logs:
        text += path.read_text(encoding="utf-8", errors="replace") + "\n"
    if newest_mtime is None:
        # No log yet: fall back to the dispatch start, else the directory.
        newest_mtime = attempt_dir.stat().st_mtime

    # A dispatch receipt normally sits at the attempt root. Garak instead
    # writes one receipt per scenario directory, so consider both: alive if
    # any recorded child is alive, and use the earliest recorded start.
    dispatch_paths = [attempt_dir / "dispatch.json"]
    dispatch_paths += sorted(attempt_dir.glob("*/dispatch.json"))
    dispatches = []
    root_dispatch: dict[str, Any] = {}
    for path in dispatch_paths:
        if path.is_file():
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                continue
            dispatches.append(record)
            if path == dispatch_paths[0]:
                root_dispatch = record
    dispatch = root_dispatch
    pids = [item.get("pid") for item in dispatches if item.get("pid")]
    pid = dispatch.get("pid") or (pids[0] if pids else None)
    alive = any(_pid_alive(pid_value) for pid_value in pids)

    manifest = run.manifest()
    attempts_record = (manifest.get("stages", {}).get(stage_name, {}) or {}).get(
        "attempts", []
    )
    record = next(
        (
            a
            for a in attempts_record
            if a.get("attempt_id") == attempt_dir.name
        ),
        {},
    )
    recorded_status = record.get("status") or (
        manifest.get("stages", {}).get(stage_name, {}) or {}
    ).get("status")

    meaningful = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not _NOISE_RE.search(line)
    ]
    errors = [line for line in meaningful if _ERROR_RE.search(line)]
    retries = [line for line in meaningful if _RETRY_RE.search(line)]
    milestones = [line for line in meaningful if _MILESTONE_RE.search(line)]
    last_milestone = milestones[-1][:300] if milestones else None
    last_error = extract_error_summary(text)
    if last_error is None and errors:
        last_error = errors[-1][:300]

    now = time.time()
    last_log_age = max(0.0, now - newest_mtime)
    started = dispatch.get("started_at") or min(
        (item.get("started_at") for item in dispatches if item.get("started_at")),
        default=None,
    )
    elapsed = None
    if started:
        try:
            from datetime import datetime, timezone

            started_dt = datetime.fromisoformat(started)
            elapsed = round(
                (datetime.now(timezone.utc) - started_dt).total_seconds(), 1
            )
        except ValueError:
            elapsed = None

    if alive:
        if last_log_age >= stall_seconds:
            health = "stalled"
        elif retries and _recent_retry(text):
            health = "retrying"
        else:
            health = "running"
    elif recorded_status in ("failed", "blocked", "needs_review"):
        health = recorded_status
    elif recorded_status in ("completed", "completed_with_gaps"):
        health = "done"
    elif pid:
        health = "stopped"
    else:
        health = "unknown"

    hints = {
        "running": "Progressing; relay the last milestone.",
        "retrying": (
            "The model client is retrying requests — tell the user now, then "
            "report whether it recovers or exhausts retries."
        ),
        "stalled": (
            f"No log activity for {int(last_log_age)}s — tell the user; the "
            "stage may be hung (the parent deadline will stop it)."
        ),
        "failed": (
            f"The stage failed: {last_error or recorded_status}. Retained as "
            f"attempt {attempt_dir.name}; a retry creates a new attempt."
        ),
        "blocked": f"The stage is blocked: {last_error or 'see the outcome blockers'}.",
        "needs_review": (
            "The stage is waiting for a review decision (exit 2). Tell the user "
            "and present the request; do not keep polling."
        ),
        "done": "Finished; show the outcome and the progress checklist.",
        "stopped": "The process is no longer running but the attempt has no outcome record.",
        "unknown": "No dispatch receipt; inspect the attempt directory.",
        "no-attempt": "The stage has not started.",
    }
    return {
        "stage": stage_name,
        "attempt": attempt_dir.name,
        "attempt_dir": run.rel(attempt_dir),
        "health": health,
        "running": alive,
        "recorded_status": recorded_status,
        "elapsed_seconds": elapsed,
        "last_log_age_seconds": round(last_log_age, 1),
        "line_count": len(text.splitlines()),
        "retry_count": len(retries),
        "error_count": len(errors),
        "last_milestone": last_milestone,
        "last_error": last_error,
        "hint": hints.get(health, ""),
    }


def _recent_retry(text: str) -> bool:
    """Whether retries appear near the end of the log (currently failing)."""
    tail = "\n".join(text.splitlines()[-40:])
    return bool(_RETRY_RE.search(tail))


def render_health(summary: dict[str, Any]) -> str:
    """One-line, human-readable health for an agent to relay verbatim."""
    stage = summary.get("stage") or "stage"
    health = summary.get("health")
    parts = [f"[asago-runner] {stage}: {health}"]
    if summary.get("attempt"):
        parts.append(f"attempt {summary['attempt']}")
    if summary.get("elapsed_seconds") is not None:
        parts.append(f"{int(summary['elapsed_seconds'])}s elapsed")
    if health == "running" and summary.get("last_milestone"):
        parts.append(f"last milestone: {summary['last_milestone'][:160]}")
    if summary.get("retry_count"):
        parts.append(f"{summary['retry_count']} retries in log")
    if summary.get("last_error") and health in ("failed", "blocked", "retrying"):
        parts.append(f"error: {summary['last_error'][:200]}")
    if summary.get("hint"):
        parts.append(summary["hint"])
    return " | ".join(parts)
