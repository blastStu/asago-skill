"""Review boundaries: request files, response files and hash bindings.

A review is a JSON request file describing exactly the material to review
(with content digests), and a JSON response file recording the visible
answer. Approval binds to the hashed batch; if any bound input or derived
material changes, the recorded decision is invalidated and re-review is
required. No approval is inferred from elapsed time or stage progression.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .evidence import RunDir, atomic_write_json, read_json, utc_now_iso
from .hashing import sha256_file

REVIEW_SCHEMA_VERSION = 1


@dataclass
class ReviewRequest:
    """A persisted request for human review."""

    kind: str  # e.g. "input-readiness", "policy-conflict", "test-plan"
    question: str
    material: list[dict]  # [{path, sha256, description}] — exact versions covered
    summary: dict[str, Any]
    response_path: Path
    request_path: Path
    extras: dict[str, Any] = field(default_factory=dict)

    def write(self) -> Path:
        payload = {
            "schema_version": REVIEW_SCHEMA_VERSION,
            "kind": self.kind,
            "created_at": utc_now_iso(),
            "question": self.question,
            "material": self.material,
            "summary": self.summary,
            "response_file": self.response_path.name,
            **self.extras,
        }
        atomic_write_json(self.request_path, payload)
        return self.request_path

    def response(self) -> dict | None:
        if self.response_path.is_file():
            return read_json(self.response_path)
        return None

    def material_digests(self) -> dict[str, str]:
        return {entry["path"]: entry["sha256"] for entry in self.material}

    def validate_response(self, response: dict) -> list[str]:
        """Check a response file against the request's hash bindings."""
        problems: list[str] = []
        if response.get("request_file") != self.request_path.name:
            problems.append("response does not name this request file")
        digests = self.material_digests()
        reviewed = response.get("reviewed_hashes") or {}
        for path, digest in digests.items():
            if path not in reviewed:
                problems.append(f"response does not bind hash of {path}")
            elif reviewed[path] != digest:
                problems.append(f"hash mismatch for {path}: material changed since request")
        if not response.get("decision"):
            problems.append("response records no decision")
        return problems


def bind_material(run: RunDir, items: list[tuple[str, str]]) -> list[dict]:
    """Build material entries ``[(path, description)]`` with current digests.

    Paths are run-relative; digests are computed from the live files so the
    request always binds what is actually on disk now.
    """
    material = []
    for rel_path, description in items:
        path = run.path / rel_path
        material.append(
            {
                "path": rel_path,
                "sha256": sha256_file(path),
                "description": description,
            }
        )
    return material


def write_review_response(
    request_path: str | Path,
    *,
    decision: str,
    actor: str,
    visible_notes: str = "",
    clarifications: list[dict] | None = None,
    extras: dict[str, Any] | None = None,
) -> Path:
    """Write a response file for a review request.

    Called by the agent/skill after the user answers; the visible exchange is
    recorded verbatim by the caller in ``clarifications``.
    """
    request_path = Path(request_path)
    request = read_json(request_path)
    digests = {entry["path"]: entry["sha256"] for entry in request.get("material", [])}
    payload = {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "request_file": request_path.name,
        "answered_at": utc_now_iso(),
        "actor": actor,
        "decision": decision,
        "reviewed_hashes": digests,
        "visible_notes": visible_notes,
        "clarifications": clarifications or [],
        **(extras or {}),
    }
    response_path = request_path.parent / request.get("response_file", "response.json")
    atomic_write_json(response_path, payload)
    return response_path
