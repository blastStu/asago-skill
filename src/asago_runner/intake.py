"""Policy intake: native parse receipts, conflict review, reconciliation.

Every supplied policy is parsed with the native mapper parser (Docling for
document formats, plain read otherwise) *before* extraction, producing an
LLM-free per-document receipt: original hash, parser/options, parsed-text
hash, lengths, and error/empty status. An empty plaintext input can be
filtered silently by the mapper's pipeline; a near-empty Docling conversion
raises in the parser. Both must be visible here, and neither is evidence that
a policy raised no risks.

For multiple documents the runner prepares a conflict review request (the
agent presents suspected disagreements with actual passages; this is
interpretive and cannot certify that every conflict was found). If user
precedence changes the effective input, a reconciled effective policy is
built from *verbatim* span selections of the preserved parsed originals, with
a span map back to document + character ranges; a model-free check verifies
every effective passage is a verbatim slice. Losing passages stay in the
evidence. Rewrites/translations/supplements are never silently substituted;
they are separately labelled derivations requiring explicit review.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .evidence import RunDir, atomic_write_json, read_json
from .hashing import sha256_file, sha256_text

SUPPORTED_SUFFIXES = {".md", ".txt", ".pdf", ".docx", ".html", ".htm", ".pptx", ".xlsx"}


class IntakeError(ValueError):
    pass


@dataclass
class ParseReceipt:
    source: str
    status: str  # ok | error | error-empty
    error: str | None
    original_sha256: str
    parser: str
    ocr: bool
    parsed_text_sha256: str | None
    parsed_chars: int | None
    parsed_words: int | None
    parsed_text_path: str | None

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "status": self.status,
            "error": self.error,
            "original_sha256": self.original_sha256,
            "parser": self.parser,
            "ocr": self.ocr,
            "parsed_text_sha256": self.parsed_text_sha256,
            "parsed_chars": self.parsed_chars,
            "parsed_words": self.parsed_words,
            "parsed_text_path": self.parsed_text_path,
        }


def parse_receipts(
    run: RunDir, policy_paths: list[Path], *, ocr: bool = False
) -> list[ParseReceipt]:
    """Produce per-document intake receipts using the native parser.

    Runs in-process against the real mapper parser (Docling for document
    formats). Local parser/OCR model assets may download on first use for
    document formats; that is a local asset fetch, not an inference request.
    """
    receipts: list[ParseReceipt] = []
    parsed_dir = run.path / "derived" / "parsed"
    parsed_dir.mkdir(parents=True, exist_ok=True)
    for path in policy_paths:
        if path.suffix.lower() not in SUPPORTED_SUFFIXES:
            receipts.append(
                ParseReceipt(
                    source=str(path),
                    status="error",
                    error=(
                        f"unsupported format {path.suffix!r}; supported: "
                        f"{sorted(SUPPORTED_SUFFIXES)}"
                    ),
                    original_sha256=sha256_file(path),
                    parser="none",
                    ocr=ocr,
                    parsed_text_sha256=None,
                    parsed_chars=None,
                    parsed_words=None,
                    parsed_text_path=None,
                )
            )
            continue
        from asago_policy_mapper.extract.parse import parse_document

        try:
            parsed = parse_document(path, ocr=ocr)
            text = parsed.content
            receipt = ParseReceipt(
                source=str(path),
                status="ok" if text.strip() else "error-empty",
                error=None if text.strip() else (
                    "plaintext parsed to empty content; the mapper pipeline "
                    "silently filters empty documents — resolve or explicitly "
                    "exclude this input before extraction"
                ),
                original_sha256=sha256_file(path),
                parser="docling" if path.suffix.lower() in _DOCLING_SUFFIXES else "plain-text",
                ocr=ocr,
                parsed_text_sha256=sha256_text(text),
                parsed_chars=len(text),
                parsed_words=len(text.split()),
                parsed_text_path=None,
            )
            if text.strip():
                out = parsed_dir / f"{path.stem}.parsed.md"
                out.write_text(text, encoding="utf-8")
                receipt.parsed_text_path = run.rel(out)
        except Exception as exc:  # near-empty Docling conversions raise here
            receipt = ParseReceipt(
                source=str(path),
                status="error",
                error=f"native parser failed: {type(exc).__name__}: {exc}",
                original_sha256=sha256_file(path),
                parser="docling" if path.suffix.lower() in _DOCLING_SUFFIXES else "plain-text",
                ocr=ocr,
                parsed_text_sha256=None,
                parsed_chars=None,
                parsed_words=None,
                parsed_text_path=None,
            )
        receipts.append(receipt)
    payload = [r.as_dict() for r in receipts]
    atomic_write_json(run.path / "derived" / "intake-receipts.json", payload)
    return receipts


_DOCLING_SUFFIXES = {".pdf", ".docx", ".html", ".htm", ".pptx", ".xlsx", ".md"}


# ---------------------------------------------------------------------------
# Conflict review and reconciliation
# ---------------------------------------------------------------------------


def prepare_conflict_review(run: RunDir, receipts: list[ParseReceipt]) -> dict:
    """Prepare the policy-conflict review request for multi-document input.

    Conflict *detection* is agent-assisted and interpretive; this runner only
    persists the request and the exact material versions. The skill presents
    suspected disagreements with actual passages and records the visible
    thread in the response.
    """
    material = []
    for receipt in receipts:
        if receipt.parsed_text_path:
            material.append(
                {
                    "path": receipt.parsed_text_path,
                    "sha256": receipt.parsed_text_sha256,
                    "description": f"parsed text of {Path(receipt.source).name}",
                }
            )
    request = {
        "kind": "policy-conflict",
        "question": (
            "Do these policy documents contain conflicting requirements? If "
            "so, which requirement should take precedence where they overlap? "
            "A precedence resolution that changes the effective input will "
            "produce a separately reviewed reconciled document with a span "
            "map back to the originals."
        ),
        "material": material,
        "single_document": len(receipts) < 2,
    }
    return request


def effective_inputs(
    run: RunDir,
    receipts: list[ParseReceipt],
    conflict_response: dict | None,
) -> tuple[list[Path], str, dict]:
    """Determine the effective policy input paths for extraction.

    Returns (paths, mode, record) where mode is one of:
    - ``originals``: supplied documents unchanged;
    - ``reconciled``: a reviewed reconciled document built from verbatim
      spans of the parsed originals (precedence applied to the mapper input);
    - ``originals-with-exclusions``: some inputs explicitly excluded by review.
    """
    if conflict_response is None or len(receipts) < 2:
        return (
            [Path(r.source) for r in receipts if r.status == "ok"],
            "originals",
            {"note": "single document or no conflict review; originals used unchanged"},
        )

    decision = conflict_response.get("decision")
    if decision == "no-conflict":
        return (
            [Path(r.source) for r in receipts if r.status == "ok"],
            "originals",
            {
                "note": "conflict review resolved: no conflicting requirements found",
                "decision_id": conflict_response.get("decision_id"),
            },
        )
    if decision == "precedence-unchanged-input":
        # Document-level precedence recorded as context only: the mapper
        # receives the originals. Recorded, but explicitly NOT claimed to be
        # applied to extraction.
        return (
            [Path(r.source) for r in receipts if r.status == "ok"],
            "originals",
            {
                "note": (
                    "document-level precedence recorded for context; the mapper "
                    "has no precedence option, so the effective input is "
                    "unchanged and precedence is NOT applied to extraction"
                ),
                "decision_id": conflict_response.get("decision_id"),
            },
        )
    if decision == "reconcile":
        reconciliation = conflict_response.get("reconciliation")
        if not reconciliation:
            raise IntakeError("reconcile decision requires a reconciliation spec")
        effective_path, span_map = build_reconciled_input(run, reconciliation)
        return (
            [effective_path],
            "reconciled",
            {
                "note": "reconciled effective input built from verbatim spans",
                "effective": run.rel(effective_path),
                "span_map": run.rel(span_map),
                "decision_id": conflict_response.get("decision_id"),
            },
        )
    raise IntakeError(f"unsupported conflict decision {decision!r}")


SEPARATOR = "\n\n"


def _validated_parsed_text(run: RunDir, parsed_rel: str) -> Path:
    """Resolve a reconciliation source path safely.

    Only recorded parsed-text receipts under the run's derived/parsed
    directory are acceptable sources: no absolute paths, no ``..`` escapes,
    no arbitrary files. This is untrusted, agent-supplied input.
    """
    receipts_path = run.path / "derived" / "intake-receipts.json"
    if receipts_path.is_file():
        receipts = json.loads(receipts_path.read_text(encoding="utf-8"))
        allowed = {
            r.get("parsed_text_path") for r in receipts if r.get("parsed_text_path")
        }
    else:
        allowed = set()
    candidate = (run.path / parsed_rel).resolve()
    parsed_root = (run.path / "derived" / "parsed").resolve()
    if (
        parsed_rel.startswith("/")
        or ".." in Path(parsed_rel).parts
        or candidate.parent != parsed_root
        or (allowed and parsed_rel not in allowed)
    ):
        raise IntakeError(
            f"reconciliation source {parsed_rel!r} is not a recorded parsed "
            "text under derived/parsed; refusing to read it"
        )
    if not candidate.is_file():
        raise IntakeError(f"parsed text not found: {parsed_rel}")
    return candidate


def build_reconciled_input(run: RunDir, reconciliation: dict) -> tuple[Path, Path]:
    """Build the reconciled effective policy from verbatim span selections.

    ``reconciliation`` is a list of selections referencing parsed originals:

        [{"parsed_text": "derived/parsed/a.parsed.md", "keep_spans":
          [[start, end], ...], "purpose": "..."}]

    Spans are half-open character ranges into the parsed text. Kept spans
    are concatenated in order, separated by a blank line; omitted (losing)
    passages remain in the preserved parsed originals. Effective ranges
    account for the separators, and every span is re-verified as a
    verbatim slice of its source AND of the effective text.
    """
    parts: list[str] = []
    span_records: list[dict] = []
    effective_chars = 0
    for selection in reconciliation:
        parsed_rel = selection["parsed_text"]
        parsed_path = _validated_parsed_text(run, parsed_rel)
        text = parsed_path.read_text(encoding="utf-8")
        text_sha = sha256_text(text)
        for span in selection.get("keep_spans", []):
            start, end = int(span[0]), int(span[1])
            if not (0 <= start < end <= len(text)):
                raise IntakeError(
                    f"span [{start},{end}) out of range for {parsed_rel} "
                    f"(length {len(text)})"
                )
            slice_text = text[start:end]
            if parts:
                # Separator sits before every span after the first.
                effective_chars += len(SEPARATOR)
            parts.append(slice_text)
            span_records.append(
                {
                    "parsed_text": parsed_rel,
                    "parsed_text_sha256": text_sha,
                    "source_range": [start, end],
                    "effective_range": [effective_chars, effective_chars + len(slice_text)],
                    "verbatim": True,
                    "text_sha256": sha256_text(slice_text),
                    "purpose": selection.get("purpose", ""),
                }
            )
            effective_chars += len(slice_text)

    effective_text = SEPARATOR.join(parts)
    effective_dir = run.path / "derived" / "reconciled"
    effective_dir.mkdir(parents=True, exist_ok=True)
    effective_path = effective_dir / "effective-policy.md"
    effective_path.write_text(effective_text, encoding="utf-8")

    verification = verify_span_map(run, effective_text, span_records)
    span_map = {
        "schema_version": 1,
        "effective_text": run.rel(effective_path),
        "effective_text_sha256": sha256_text(effective_text),
        "effective_chars": len(effective_text),
        "spans": span_records,
        "verification": verification,
    }
    span_map_path = effective_dir / "span-map.json"
    atomic_write_json(span_map_path, span_map)
    if not verification["ok"]:
        raise IntakeError(
            "span map verification failed: " + "; ".join(verification["problems"])
        )
    return effective_path, span_map_path


def verify_span_map(
    run: RunDir, effective_text: str, span_records: list[dict]
) -> dict:
    """Model-free check: every effective passage is a verbatim slice.

    Re-reads each recorded source range from the preserved parsed original,
    compares its digest to the recorded ``text_sha256``, and confirms the
    recorded effective range contains exactly that slice in the effective
    text. Approved rewrites/translations are NOT allowed here; they must be
    separate, labelled derivations with their own review.
    """
    problems: list[str] = []
    for record in span_records:
        source = run.path / record["parsed_text"]
        if not source.is_file():
            problems.append(f"missing parsed source {record['parsed_text']}")
            continue
        text = source.read_text(encoding="utf-8")
        start, end = record["source_range"]
        slice_text = text[start:end]
        if sha256_text(slice_text) != record.get("text_sha256"):
            problems.append(f"source slice digest mismatch at {record['source_range']}")
            continue
        eff_start, eff_end = record["effective_range"]
        if effective_text[eff_start:eff_end] != slice_text:
            problems.append(
                f"effective range [{eff_start},{eff_end}) does not contain the "
                "recorded verbatim slice"
            )
    if problems:
        return {"ok": False, "problems": problems}
    return {"ok": True, "problems": [], "checked_slices": len(span_records)}
