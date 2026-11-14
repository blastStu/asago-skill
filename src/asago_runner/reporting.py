"""Result reporting: summary.json and the offline HTML overview.

The summary is derived in Python from retained native records, with separate
denominators for risks, scenarios, artifacts and evaluation attempts —
many-to-many lineage does not support one universal coverage percentage.
Every dropped/skipped item links a reason. Any reported attack rate carries
its actual denominator and inconclusive count.

The HTML overview is a single static file: no model calls, credentials, web
service or external scripts; all untrusted text (policy passages, attack
content, endpoint responses) is HTML-escaped.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from .evidence import RunDir, atomic_write_json, read_json

OUTCOME_LABELS = {
    "attack_succeeded": "Attack succeeded",
    "attack_not_demonstrated": "Attack not demonstrated",
    "inconclusive": "Inconclusive",
}

# The canonical, ordered journey. `status` derives a per-step state so agents
# and CLI users always render the same checklist instead of improvising.
# (step, label, owner). The owner is shown in the checklist and the welcome
# plan so users can always tell whose work a step is:
#   asago     — a real, unmodified Asago component
#   external  — an external evaluator the skill orchestrates (Garak)
#   runner    — the skill's runner: orchestration, bookkeeping, reporting
#   review    — a decision that belongs to the user
PIPELINE_STEPS = (
    ("setup", "Create the run (config snapshot, originals copied)", "runner"),
    (
        "preflight",
        "Environment check — no model calls (installs, Nexus data, credentials, schemas)",
        "runner",
    ),
    (
        "input-review",
        "Input readiness — documents, data-flow destinations, models, scope",
        "review",
    ),
    (
        "intake",
        "Parse every policy — the Policy Mapper's parser converts and checks each "
        "document (no model calls)",
        "asago",
    ),
    (
        "conflict",
        "Policy conflicts — only when several documents disagree; you decide "
        "which requirement takes precedence",
        "review",
    ),
    ("map", "Policy text → taxonomy risks with evidence spans", "asago"),
    (
        "scenarios",
        "Risks + your system context → admitted scenarios",
        "asago",
    ),
    (
        "artifacts",
        "Scenarios → validated artifacts + replay entries",
        "asago",
    ),
    (
        "test-plan",
        "Test plan — the exact replay batch before anything reaches the target",
        "review",
    ),
    (
        "evaluate",
        "Replay entries against your target (evaluator + judge)",
        "external",
    ),
    ("report", "summary.json + offline HTML overview", "runner"),
    ("verify", "Model-free consistency check of all evidence", "runner"),
)

_WORK_TAGS = {
    "asago": "[ASAGO COMPONENT]",
    "external": "[EXTERNAL: GARAK]",
    "runner": "[RUNNER]",
    "review": "[YOUR REVIEW]",
}

_WORK_DESCRIPTIONS = {
    "asago": "the real Asago library, unmodified",
    "external": "external evaluator run by the skill",
    "runner": "orchestration, bookkeeping and reporting only",
    "review": "a decision that belongs to you",
}


def _legend_for(owners) -> str:
    """A legend line listing only the owner tags actually in use."""
    order = ("asago", "external", "runner", "review")
    parts = [
        f"{_WORK_TAGS[owner]} = {_WORK_DESCRIPTIONS[owner]}"
        for owner in order
        if owner in owners
    ]
    return "  Labels: " + " ·\n          ".join(parts)


# The checklist always includes every owner kind, so its legend is the full
# one (derived, not duplicated).
_WORK_LEGEND = _legend_for(set(_WORK_TAGS))

_STEP_ICONS = {
    "done": "[x]",
    "done_with_gaps": "[x]",
    "needs_review": "[!]",
    "failed": "[X]",
    "blocked": "[!]",
    "skipped": "[-]",
    "not_applicable": "[–]",
    "not_started": "[ ]",
}


def derive_progress(manifest: dict, run_path: Path | None = None) -> list[dict]:
    """Derive the ordered per-step state of a run for a progress checklist."""
    flow = manifest.get("flow", {})
    stages = manifest.get("stages", {})
    subject = manifest.get("subject", "built")
    states: dict[str, str] = {}

    if subject == "proposed":
        # Design-time run: everything after the Scenario Generator is
        # deliberately out of scope — the described agent is not built.
        for step in ("artifacts", "test-plan", "evaluate"):
            states[step] = "skipped"

    states["setup"] = "done" if manifest.get("run_id") else "not_started"

    review = flow.get("input_readiness_review", {}).get("state")
    if review == "resolved":
        states["preflight"] = "done"
        states["input-review"] = "done"
    elif review == "pending":
        states["preflight"] = "done"
        states["input-review"] = "needs_review"
    else:
        states["preflight"] = "not_started"
        states["input-review"] = "not_started"

    conflict_state = flow.get("conflict_review", {}).get("state")
    receipts = None
    if run_path is not None:
        receipts_path = run_path / "derived" / "intake-receipts.json"
        if receipts_path.is_file():
            try:
                receipts = json.loads(receipts_path.read_text(encoding="utf-8"))
            except ValueError:
                receipts = None
    # Parsing is the Policy Mapper's own parser (component work); the
    # conflict decision that follows is a user review, tracked separately.
    # A receipt is not proof of success: an empty or unparseable document
    # leaves a receipt with a non-"ok" status and intake exits blocked.
    intake_failed = isinstance(receipts, list) and any(
        (item or {}).get("status") != "ok" for item in receipts
    )
    if intake_failed:
        states["intake"] = "blocked"
    elif "effective_inputs" in flow or conflict_state == "pending" or receipts:
        states["intake"] = "done"
    else:
        states["intake"] = "not_started"
    if conflict_state == "pending":
        states["conflict"] = "needs_review"
    elif conflict_state == "resolved":
        states["conflict"] = "done"
    elif "effective_inputs" in flow:
        # Single-document runs never create a conflict review.
        states["conflict"] = "not_applicable"
    else:
        states["conflict"] = "not_started"

    def stage_state(name: str, flow_key: str) -> str:
        record = stages.get(name, {})
        if flow.get(flow_key):
            status = record.get("status")
            if status == "completed":
                return "done"
            if status == "completed_with_gaps":
                return "done_with_gaps"
            return "done_with_gaps" if status else "done"
        if record.get("attempts"):
            latest = record.get("latest_attempt_status") or record.get("status")
            if latest == "needs_review":
                return "needs_review"
            if latest in ("failed", "blocked"):
                return "blocked" if latest == "blocked" else "failed"
            return record.get("status", "not_started")
        return "not_started"

    states["map"] = stage_state("policy-mapper", "mapper_output")
    states["scenarios"] = stage_state("scenario-generator", "scenario_handoff")
    if "artifacts" not in states:
        states["artifacts"] = stage_state("artifact-generator", "replay_entries")

    test_plan = flow.get("test_plan_review", {}).get("state")
    if "test-plan" not in states:
        states["test-plan"] = (
            "done" if test_plan == "resolved"
            else "needs_review" if test_plan == "pending"
            else "not_started"
        )

    if "evaluate" not in states:
        garak = stages.get("garak", {})
        if garak.get("status") == "completed":
            states["evaluate"] = "done"
        elif garak.get("status") == "completed_with_gaps":
            states["evaluate"] = "done_with_gaps"
        elif garak.get("attempts"):
            states["evaluate"] = garak.get("status", "failed")
        else:
            states["evaluate"] = "not_started"

    if run_path is not None and (run_path / "reports" / "summary.json").is_file():
        states["report"] = "done"
    else:
        states["report"] = "not_started"

    verify = manifest.get("verify_run")
    if verify is None:
        states["verify"] = "not_started"
    elif verify.get("ok"):
        states["verify"] = "done"
    else:
        states["verify"] = "failed"

    return [
        {
            "step": step,
            "label": label,
            "owner": owner,
            "state": states.get(step, "not_started"),
        }
        for step, label, owner in PIPELINE_STEPS
    ]


# ---------------------------------------------------------------------------
# The welcome plan
#
# This is the only place the opening plan text lives. The runner prints it
# (`asago-runner plan`) and the skill quotes it verbatim, so the journey a
# user sees is identical every run and cannot be paraphrased, reordered or
# embellished by an agent.
# ---------------------------------------------------------------------------

# User-facing title + one-sentence explanation per step. Ownership comes from
# PIPELINE_STEPS so the tags can never drift from the checklist.
_PLAN_COPY = {
    "preflight": (
        "Check the environment",
        "installs, the IBM risk data, your model connections (no model calls yet)",
    ),
    "input-review": (
        "Input readiness",
        "you approve the documents, where their text will be sent, the models "
        "and the scope",
    ),
    "intake": (
        "Parse your policies",
        "the Policy Mapper's own parser reads and checks every document "
        "(no model calls)",
    ),
    "conflict": (
        "Policy conflicts",
        "only if you supplied several documents that disagree: you decide "
        "which requirement takes precedence",
    ),
    "map": (
        "Policy Mapper",
        "your policy text becomes a risk landscape with evidence pointing back "
        "at your own words",
    ),
    "scenarios": (
        "Scenario Generator",
        "those risks, combined with your system description, become concrete "
        "attack scenarios",
    ),
    "artifacts": (
        "Artifact Generator",
        "scenarios become validated replay conversations (it checks each one "
        "can be represented before spending model calls)",
    ),
    "test-plan": (
        "Test plan",
        "you see the exact conversation that will be sent to your target, and "
        "approve it",
    ),
    "evaluate": (
        "Evaluate",
        "the replay is sent to your target and judged",
    ),
    "report": (
        "Report and verify",
        "an offline HTML overview, and a consistency check of all the evidence",
    ),
}

# Steps that only exist for a built system, plus internal steps that are not
# part of the user-facing journey (run creation is implicit).
_BUILT_ONLY_STEPS = {"artifacts", "test-plan", "evaluate"}
_NOT_IN_PLAN = {"setup", "verify"}
# Steps that always need a decision from the user.
_ALWAYS_REVIEW_STEPS = {"input-review", "test-plan"}


def render_plan(subject: str = "built") -> str:
    """Render the deterministic welcome plan for a built or proposed subject."""
    if subject not in ("built", "proposed"):
        raise ValueError("subject must be 'built' or 'proposed'")
    proposed = subject == "proposed"
    steps = [
        (step, owner)
        for step, _label, owner in PIPELINE_STEPS
        if step not in _NOT_IN_PLAN
        and not (proposed and step in _BUILT_ONLY_STEPS)
    ]
    lines = [
        "Welcome to Asago. Here's what we're going to do, in order — each step "
        "shows whose work it is:",
        "",
    ]
    numbers: dict[str, int] = {}
    for index, (step, owner) in enumerate(steps, start=1):
        numbers[step] = index
        title, detail = _PLAN_COPY[step]
        if proposed and step == "preflight":
            detail = (
                "installs, the IBM risk data, your two generation-model "
                "connections (no model calls yet)"
            )
        if proposed and step == "report":
            detail = (
                "the threat picture for your design, with the evidence trail"
            )
        lines.append(f"{index}. {_WORK_TAGS[owner]} {title} — {detail}")
    lines.append("")
    if proposed:
        lines.append(
            "In short: the analysis is the Asago components'; the skill only "
            "orchestrates and reports."
        )
    else:
        lines.append(
            "In short: the analysis is the Asago components' (and Garak's); "
            "the skill only orchestrates, records and reports."
        )
    review_numbers = [
        str(numbers[step])
        for step in ("input-review", "test-plan")
        if step in numbers
    ]
    conflict_number = numbers.get("conflict")
    if len(review_numbers) == 2:
        decision_line = (
            f"Two steps always need decisions from you ("
            f"{review_numbers[0]} and {review_numbers[1]})"
        )
    elif len(review_numbers) == 1:
        decision_line = f"One step always needs a decision from you ({review_numbers[0]})"
    else:
        decision_line = "No step needs a decision from you"
    if conflict_number is not None:
        decision_line += (
            f"; step {conflict_number} only when several policies disagree"
        )
    lines.append(decision_line + ". The rest run on their own.")
    if proposed:
        lines.append("")
        lines.append(
            "We deliberately stop after the scenarios: there's no built system "
            "to attack yet, so no evaluation happens and you don't need a "
            "target endpoint. When you do build it, we can pick up from these "
            "same policies and run the full chain."
        )
    lines.append("")
    lines.append(_legend_for({owner for _step, owner in steps}))
    return "\n".join(lines)


def render_progress_checklist(progress: list[dict], run_id: str | None = None) -> str:
    """A human-readable checklist block for terminals and agent narration.

    Every line names whose work the step is (Asago component, external
    evaluator, runner orchestration, or a user review), so users can see
    where the real component analysis happens.
    """
    lines = [f"Asago run progress{f' (run {run_id})' if run_id else ''}:"]
    for item in progress:
        icon = _STEP_ICONS.get(item["state"], "[ ]")
        tag = _WORK_TAGS.get(item.get("owner", "runner"), "[RUNNER]")
        note = ""
        if item["state"] == "done_with_gaps":
            note = "  (completed with gaps — see the stage output)"
        elif item["state"] == "needs_review":
            note = "  ← waiting on you"
        elif item["state"] == "failed":
            note = "  (failed — see blockers/attempt logs)"
        elif item["state"] == "blocked":
            note = "  (blocked — see blockers)"
        elif item["state"] == "skipped":
            note = (
                "  (design-time run: the proposed agent is not built — "
                "stops after the Scenario Generator by design)"
            )
        elif item["state"] == "not_applicable":
            note = "  (not needed: single policy document)"
        lines.append(f"  {icon} {tag:<17} {item['step']:<12} {item['label']}{note}")
    remaining = sum(1 for i in progress if i["state"] == "not_started")
    lines.append(f"  {remaining} step(s) remaining.")
    lines.append(_WORK_LEGEND)
    return "\n".join(lines)


def build_summary(run: RunDir) -> dict:
    """Derive reports/summary.json from the retained evidence tree."""
    manifest = run.manifest()
    summary: dict[str, Any] = {
        "schema_version": 1,
        "run_id": manifest.get("run_id"),
        "label": manifest.get("label"),
        "subject": manifest.get("subject", "built"),
        "created_at": manifest.get("created_at"),
        "generated_at": run.manifest().get("updated_at"),
        "stages": {},
        "funnel": {},
        "selections": [],
        "evaluations": [],
        "gaps": [],
        "shared_model_roles": manifest.get("shared_model_roles", []),
        "tested_surface": None,
        "notes": [],
    }
    if manifest.get("subject") == "proposed":
        summary["notes"].append(
            "design-time run: the subject is a proposed design, not a built "
            "system. The run stops after the Scenario Generator; the "
            "scenarios below are the threat picture for the design as "
            "described. No artifacts were generated and no evaluation was "
            "attempted or is possible until the system is built."
        )

    stages = manifest.get("stages", {})
    for stage, record in stages.items():
        summary["stages"][stage] = {
            "status": record.get("status"),
            "latest_attempt": record.get("latest_attempt"),
        }

    # Mapper accounting
    mapper_attempts = (stages.get("policy-mapper") or {}).get("attempts", [])
    latest_mapper = next(
        (a for a in reversed(mapper_attempts) if a.get("accounting")), None
    )
    if latest_mapper:
        accounting = latest_mapper["accounting"]
        summary["funnel"]["risks"] = {
            "matched_total": accounting["risks_total"],
            "downstream_supported": accounting["risks_downstream_supported"],
            "per_taxonomy": accounting["risks_per_taxonomy"],
            "denominator_note": (
                "denominator: risks matched by the mapper in this run; "
                "unsupported taxonomies are visible but not testable downstream"
            ),
        }
        summary["gaps"].extend(accounting.get("gaps", []))

    # Scenario accounting
    scenario_attempts = (stages.get("scenario-generator") or {}).get("attempts", [])
    latest_scenario = next(
        (a for a in reversed(scenario_attempts) if a.get("inventory_summary")), None
    )
    if latest_scenario:
        inv = latest_scenario["inventory_summary"]
        summary["funnel"]["scenarios"] = {
            "admitted": inv.get("admitted"),
            "quarantined": inv.get("quarantined"),
            "denominator_note": (
                "denominator: admitted scenarios from the native "
                "finalization inventory; quarantined/failed remain visible"
            ),
        }

    # Artifact + replay accounting
    artifact_attempts = (stages.get("artifact-generator") or {}).get("attempts", [])
    latest_artifact = next(
        (a for a in reversed(artifact_attempts) if a.get("replay_entries")), None
    )
    if latest_artifact:
        entries = latest_artifact["replay_entries"]
        summary["funnel"]["artifacts"] = {
            "validated_candidates": latest_artifact.get("candidate_count"),
            "replay_entries": len(entries),
            "denominator_note": (
                "denominator: structurally validated artifacts with a "
                "supported transport; skipped/partial/invalid items are "
                "recorded separately"
            ),
        }
        surfaces = sorted({e.get("surface") for e in entries if e.get("surface")})
        summary["tested_surface"] = surfaces
        summary["selections"] = entries

    # Garak evaluations
    garak_attempts = (stages.get("garak") or {}).get("attempts", [])
    evaluations = []
    for attempt in garak_attempts:
        for dispatch in attempt.get("dispatches", []):
            evaluations.append(
                {
                    "scenario_id": dispatch.get("scenario_id"),
                    "outcome": dispatch.get("outcome"),
                    "reason": dispatch.get("reason"),
                    "judge_confidence": dispatch.get("judge_confidence"),
                    "detector_score": dispatch.get("detector_score"),
                    "surface": dispatch.get("surface"),
                    "dispatch_dir": dispatch.get("dispatch_dir"),
                }
            )
    summary["evaluations"] = evaluations
    if evaluations:
        succeeded = sum(1 for e in evaluations if e["outcome"] == "attack_succeeded")
        not_demonstrated = sum(
            1 for e in evaluations if e["outcome"] == "attack_not_demonstrated"
        )
        inconclusive = sum(1 for e in evaluations if e["outcome"] == "inconclusive")
        usable = succeeded + not_demonstrated
        summary["funnel"]["evaluations"] = {
            "dispatched": len(evaluations),
            "usable": usable,
            "attack_succeeded": succeeded,
            "attack_not_demonstrated": not_demonstrated,
            "inconclusive": inconclusive,
            "attack_rate_note": (
                f"attack rate {succeeded}/{usable} usable evaluations "
                f"({inconclusive} inconclusive excluded from the denominator)"
                if usable
                else "no usable evaluations; no attack rate is reported"
            ),
        }

    if manifest.get("verify_run"):
        summary["verify_run"] = manifest["verify_run"]
    return summary



def render_html(
    run: RunDir, summary: dict, conversation: str | None = None
) -> Path:
    """Render the offline HTML report from the derived summary detail.

    ``conversation`` is an optional, already-read transcript of the session
    that ran the skill. It is rendered as escaped text; its content is not
    written to summary.json.
    """
    from .report_page import collect_report_data, render_page

    # Raw policy passages, attacks and model output belong in the HTML page
    # only. summary.json stays a machine-readable view of statuses, counts
    # and paths, so it can be read or shared without carrying the material.
    data = collect_report_data(run, summary)
    out = render_page(run, summary, data, conversation=conversation)
    atomic_write_json(run.path / "reports" / "summary.json", summary)
    return out
