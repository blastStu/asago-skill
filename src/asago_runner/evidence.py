"""Durable evidence: run directories, manifests, inventory and decisions.

Evidence is ordinary files under a run directory, written atomically, with an
append-only decision journal and a flat SHA-256 inventory. This is a migration
foundation for later OSCAL export, not an OSCAL compliance claim.

Layout (information categories from the Phase 1 evidence contract):

    run/
      run.json                 run/config/dependency identities, scope, status
      inventory.json           retained file paths, roles, SHA-256 digests
      decisions.jsonl          append-only visible decisions and review bindings
      run.lock                 writer exclusion while a command holds the run
      originals/               policy documents and supplied context
      derived/                 parsed/reconciled/effective inputs, span maps
      reviews/                 material presented, requests, visible responses
      preflight/               dependency/data/facts checks and findings
      stages/<stage>/<attempt>/ native outputs + adapter/attempt metadata
      reports/                 summary.json and the offline HTML overview
"""

from __future__ import annotations

import json
import os
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .hashing import sha256_file

RUN_SCHEMA_VERSION = 1
INVENTORY_SCHEMA_VERSION = 1
DECISION_SCHEMA_VERSION = 1

# Files that belong to the evidence machinery itself and are never inventoried
# as payload (a self-referential inventory checksum is avoided by design).
_INVENTORY_SELF_EXCLUDE = {"inventory.json", "run.lock"}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    """A short, unique, sortable id such as ``D0003-ab12cd``."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def atomic_write_text(path: str | Path, text: str) -> None:
    """Write text atomically: temp file in the same directory, then rename."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f".{target.name}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
    finally:
        tmp.unlink(missing_ok=True)


def atomic_write_json(path: str | Path, payload: Any) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=False) + "\n")


def read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Run directories and locking
# ---------------------------------------------------------------------------


class RunLockError(RuntimeError):
    """Another writer currently holds the run."""


class RunDir:
    """Access to one run's evidence tree with writer exclusion."""

    def __init__(self, path: str | Path):
        self.path = Path(path).resolve()
        if not (self.path / "run.json").is_file():
            raise FileNotFoundError(
                f"{self.path} is not a run directory (run.json missing)"
            )


    # -- construction ------------------------------------------------------

    @classmethod
    def create(cls, path: str | Path) -> "RunDir":
        root = Path(path).resolve()
        root.mkdir(parents=True, exist_ok=False)
        for sub in (
            "originals",
            "derived",
            "reviews",
            "preflight",
            "reports",
            "stages/policy-mapper",
            "stages/scenario-generator",
            "stages/artifact-generator",
            "stages/garak",
        ):
            (root / sub).mkdir(parents=True, exist_ok=True)
        atomic_write_json(root / "run.json", {"schema_version": RUN_SCHEMA_VERSION})
        return cls(root)

    # -- paths --------------------------------------------------------------

    def rel(self, path: str | Path) -> str:
        return str(Path(path).resolve().relative_to(self.path))

    def stage_dir(self, stage: str) -> Path:
        return self.path / "stages" / stage

    def new_attempt_dir(self, stage: str) -> tuple[str, Path]:
        """Allocate the next attempt directory for a stage."""
        base = self.stage_dir(stage)
        existing = [p.name for p in base.iterdir() if p.is_dir()] if base.is_dir() else []
        seq = len(existing) + 1
        attempt_id = f"{seq:04d}-{uuid.uuid4().hex[:6]}"
        attempt_dir = base / attempt_id
        attempt_dir.mkdir(parents=True, exist_ok=False)
        return attempt_id, attempt_dir

    # -- run manifest -------------------------------------------------------

    @property
    def manifest_path(self) -> Path:
        return self.path / "run.json"

    def manifest(self) -> dict:
        return read_json(self.manifest_path)

    def update_manifest(self, mutate) -> dict:
        """Load run.json, apply ``mutate(manifest)``, write atomically."""
        manifest = self.manifest()
        mutate(manifest)
        atomic_write_json(self.manifest_path, manifest)
        return manifest

    def record_stage_attempt(self, stage: str, attempt_id: str, record: dict) -> None:
        """Record attempt start before invoking a component (crash-safe)."""

        def mutate(manifest: dict) -> None:
            record.setdefault("attempt_id", attempt_id)
            manifest.setdefault("stages", {}).setdefault(stage, {}).setdefault(
                "attempts", []
            ).append(record)
            manifest["stages"][stage]["latest_attempt"] = attempt_id

        self.update_manifest(mutate)

    def record_stage_outcome(self, stage: str, attempt_id: str, record: dict) -> None:
        """Record attempt completion/failure afterwards."""

        def mutate(manifest: dict) -> None:
            stage_rec = manifest.setdefault("stages", {}).setdefault(stage, {})
            attempts = stage_rec.setdefault("attempts", [])
            for attempt in attempts:
                if attempt.get("attempt_id") == attempt_id:
                    attempt.update(record)
                    break
            else:
                attempts.append({"attempt_id": attempt_id, **record})
            stage_rec["latest_attempt"] = attempt_id
            stage_rec["status"] = record.get("status")

        self.update_manifest(mutate)

    # -- locking ------------------------------------------------------------

    def acquire_lock(self, holder: str) -> None:
        lock_path = self.path / "run.lock"
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            try:
                stale_note = lock_path.read_text(encoding="utf-8").strip()
            except OSError:
                stale_note = "(unreadable)"
            raise RunLockError(
                f"run is locked by another writer (lock note: {stale_note})"
            ) from exc
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f"{holder} pid={os.getpid()} at={utc_now_iso()}\n")

    def release_lock(self) -> None:
        (self.path / "run.lock").unlink(missing_ok=True)

    @contextmanager
    def locked(self, holder: str) -> Iterator["RunDir"]:
        self.acquire_lock(holder)
        try:
            yield self
        finally:
            self.release_lock()

    # -- decision journal ----------------------------------------------------

    @property
    def decisions_path(self) -> Path:
        return self.path / "decisions.jsonl"

    def append_decision(self, record: dict) -> str:
        """Append one decision record; returns the decision id.

        Records are append-only. A correction supersedes an earlier record by
        referencing its id; it never rewrites it.
        """
        record = {
            "schema_version": DECISION_SCHEMA_VERSION,
            "id": record.get("id") or new_id("D"),
            "recorded_at": utc_now_iso(),
            **record,
        }
        line = json.dumps(record, sort_keys=False)
        with open(self.decisions_path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return record["id"]

    def decisions(self) -> list[dict]:
        if not self.decisions_path.is_file():
            return []
        records = []
        for line in self.decisions_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
        return records

    def resolved_decision(self, category: str) -> dict | None:
        """Latest non-invalidated, resolved decision in a category."""
        found = None
        for record in self.decisions():
            if record.get("category") == category and record.get("state") == "resolved":
                found = record
        return found

    # -- inventory ------------------------------------------------------------

    @property
    def inventory_path(self) -> Path:
        return self.path / "inventory.json"

    def rebuild_inventory(self) -> dict:
        """Hash every payload file in the run; write inventory.json.

        The inventory itself and the lock are excluded so the record is not
        self-referential. Called after stage completion; a crash before the
        rewrite leaves the previous inventory valid for prior files.
        """
        entries = []
        for path in sorted(self.path.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(self.path).as_posix()
            if rel in _INVENTORY_SELF_EXCLUDE or rel.startswith("."):
                continue
            entries.append(
                {
                    "path": rel,
                    "role": _role_for(rel),
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
        payload = {
            "schema_version": INVENTORY_SCHEMA_VERSION,
            "generated_at": utc_now_iso(),
            "file_count": len(entries),
            "files": entries,
        }
        atomic_write_json(self.inventory_path, payload)
        return payload

    def inventory(self) -> dict:
        return read_json(self.inventory_path)

    def inventory_digest(self, path: str | Path) -> str | None:
        """Digest recorded in the current inventory for a run-relative path."""
        rel = path if isinstance(path, str) else self.rel(path)
        for entry in self.inventory().get("files", []):
            if entry["path"] == rel:
                return entry["sha256"]
        return None


def _role_for(rel: str) -> str:
    top = rel.split("/", 1)[0]
    if top == "originals":
        return "original-input"
    if top == "derived":
        return "derived-input"
    if top == "reviews":
        return "review"
    if top == "preflight":
        return "preflight"
    if top == "stages":
        return "stage-output"
    if top == "reports":
        return "report"
    return "run-record"


# ---------------------------------------------------------------------------
# Attempt timing helper
# ---------------------------------------------------------------------------


class Stopwatch:
    """Monotonic timing for stage/attempt records."""

    def __init__(self) -> None:
        self.start_mono = time.monotonic()
        self.start_iso = utc_now_iso()

    def lap(self) -> dict:
        return {
            "start": self.start_iso,
            "end": utc_now_iso(),
            "duration_seconds": round(time.monotonic() - self.start_mono, 3),
        }
