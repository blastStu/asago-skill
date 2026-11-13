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
PIPELINE_STEPS = (
    ("setup", "Create the run (config snapshot, originals copied)"),
    ("preflight", "Environment check — no model calls (installs, Nexus data, credentials, schemas)"),
    ("input-review", "YOUR REVIEW: input readiness — documents, data-flow destinations, models, scope"),
    ("intake", "Policy intake — native parse receipts; conflict review if multiple policies"),
    ("map", "Policy Mapper — policy text → taxonomy risks with evidence spans"),
    ("scenarios", "Scenario Generator — risks + your system context → admitted scenarios"),
    ("artifacts", "Artifact Generator — scenarios → validated artifacts + replay entries"),
    ("test-plan", "YOUR REVIEW: test plan — the exact replay batch before anything reaches the target"),
    ("evaluate", "Evaluation — replay entries against your target (Garak + judge)"),
    ("report", "Report — summary.json + offline HTML overview"),
    ("verify", "verify-run — model-free consistency check of all evidence"),
)

_STEP_ICONS = {
    "done": "[x]",
    "done_with_gaps": "[x]",
    "needs_review": "[!]",
    "failed": "[X]",
    "blocked": "[!]",
    "not_started": "[ ]",
}


def derive_progress(manifest: dict, run_path: Path | None = None) -> list[dict]:
    """Derive the ordered per-step state of a run for a progress checklist."""
    flow = manifest.get("flow", {})
    stages = manifest.get("stages", {})
    states: dict[str, str] = {}

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

    if flow.get("effective_inputs"):
        states["intake"] = "done"
    elif flow.get("conflict_review", {}).get("state") == "pending":
        states["intake"] = "needs_review"
    else:
        states["intake"] = "not_started"

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
    states["artifacts"] = stage_state("artifact-generator", "replay_entries")

    test_plan = flow.get("test_plan_review", {}).get("state")
    states["test-plan"] = (
        "done" if test_plan == "resolved"
        else "needs_review" if test_plan == "pending"
        else "not_started"
    )

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
        {"step": step, "label": label, "state": states.get(step, "not_started")}
        for step, label in PIPELINE_STEPS
    ]


def render_progress_checklist(progress: list[dict], run_id: str | None = None) -> str:
    """A human-readable checklist block for terminals and agent narration."""
    lines = [f"Asago run progress{f' (run {run_id})' if run_id else ''}:"]
    for item in progress:
        icon = _STEP_ICONS.get(item["state"], "[ ]")
        note = ""
        if item["state"] == "done_with_gaps":
            note = "  (completed with gaps — see the stage output)"
        elif item["state"] == "needs_review":
            note = "  ← waiting on you"
        elif item["state"] == "failed":
            note = "  (failed — see blockers/attempt logs)"
        elif item["state"] == "blocked":
            note = "  (blocked — see blockers)"
        lines.append(f"  {icon} {item['step']:<13} {item['label']}{note}")
    remaining = sum(1 for i in progress if i["state"] == "not_started")
    lines.append(f"  {remaining} step(s) remaining.")
    return "\n".join(lines)


def build_summary(run: RunDir) -> dict:
    """Derive reports/summary.json from the retained evidence tree."""
    manifest = run.manifest()
    summary: dict[str, Any] = {
        "schema_version": 1,
        "run_id": manifest.get("run_id"),
        "label": manifest.get("label"),
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


def render_html(run: RunDir, summary: dict) -> Path:
    """Render the offline HTML overview with escaped untrusted content."""
    e = html.escape
    rows: list[str] = []

    def stage_row(name: str, record: dict) -> str:
        status = record.get("status") or "not-run"
        color = {
            "completed": "#1a7f37",
            "completed_with_gaps": "#9a6700",
            "needs_review": "#9a6700",
            "blocked": "#cf222e",
            "failed": "#cf222e",
        }.get(status, "#57606a")
        return (
            f"<tr><td>{e(name)}</td>"
            f"<td><span style='color:{color};font-weight:600'>{e(status)}</span></td>"
            f"<td>{e(record.get('latest_attempt') or '')}</td></tr>"
        )

    stage_html = "".join(
        stage_row(name, record) for name, record in summary.get("stages", {}).items()
    ) or "<tr><td colspan=3>No stages recorded</td></tr>"

    funnel_html = ""
    for name, funnel in summary.get("funnel", {}).items():
        funnel_html += f"<h3>{e(name)}</h3><dl>"
        for key, value in funnel.items():
            if key == "denominator_note" or key == "attack_rate_note":
                funnel_html += f"<dt>{e(key)}</dt><dd class='note'>{e(str(value))}</dd>"
            elif isinstance(value, dict):
                funnel_html += (
                    f"<dt>{e(key)}</dt><dd>{e(json.dumps(value, sort_keys=True))}</dd>"
                )
            else:
                funnel_html += f"<dt>{e(key)}</dt><dd>{e(str(value))}</dd>"
        funnel_html += "</dl>"

    eval_rows = []
    for evaluation in summary.get("evaluations", []):
        outcome = evaluation.get("outcome", "inconclusive")
        color = {
            "attack_succeeded": "#cf222e",
            "attack_not_demonstrated": "#1a7f37",
            "inconclusive": "#9a6700",
        }.get(outcome, "#57606a")
        confidence = evaluation.get("judge_confidence")
        eval_rows.append(
            "<tr>"
            f"<td>{e(str(evaluation.get('scenario_id')))}</td>"
            f"<td>{e(str(evaluation.get('surface')))}</td>"
            f"<td><span style='color:{color};font-weight:600'>{e(outcome)}</span></td>"
            f"<td>{e(str(confidence) if confidence is not None else '—')}</td>"
            f"<td class='reason'>{e(str(evaluation.get('reason') or ''))}</td>"
            f"<td><a href='../{e(str(evaluation.get('dispatch_dir', '')))}'>evidence</a></td>"
            "</tr>"
        )
    eval_html = "".join(eval_rows) or "<tr><td colspan=6>No evaluations dispatched</td></tr>"

    gaps = summary.get("gaps", [])
    gaps_html = "".join(f"<li>{e(g)}</li>" for g in gaps) or "<li>None recorded</li>"

    shared = summary.get("shared_model_roles") or []
    shared_html = (
        "".join(f"<li>{e(' = '.join(group))}</li>" for group in shared)
        or "<li>No shared model roles configured</li>"
    )
    shared_note = (
        "<p class='note'>A shared target/judge model means the detector judgment "
        "lacks independent validation; separate role configuration does not "
        "establish independence.</p>"
        if shared
        else ""
    )

    surfaces = summary.get("tested_surface") or []
    surface_html = (
        "<p><strong>Tested surface(s):</strong> "
        + e(", ".join(surfaces))
        + " — a direct chat user-turn attack is labelled as such and is not "
        "indirect-injection coverage.</p>"
        if surfaces
        else ""
    )

    links = []
    for rel, label in [
        ("../stages/policy-mapper", "Policy Mapper native outputs"),
        ("../stages/scenario-generator", "Scenario Generator native outputs"),
        ("../stages/artifact-generator", "Artifact Generator native outputs"),
        ("../stages/garak", "Garak dispatch evidence"),
        ("../decisions.jsonl", "Decision journal"),
        ("../inventory.json", "Evidence inventory"),
    ]:
        path = run.path / rel.replace("../", "")
        if path.exists():
            links.append(f"<li><a href='{e(rel)}'>{e(label)}</a></li>")
    links_html = "".join(links)

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Asago run overview — {e(str(summary.get('label') or summary.get('run_id')))}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
         margin: 0 auto; max-width: 60rem; padding: 1rem 1.5rem 3rem; color: #1f2328;
         background: #fff; line-height: 1.5; }}
  h1 {{ font-size: 1.5rem; }} h2 {{ font-size: 1.2rem; margin-top: 2rem; }} h3 {{ font-size: 1rem; }}
  table {{ border-collapse: collapse; width: 100%; margin: 0.5rem 0 1rem; }}
  th, td {{ border: 1px solid #d0d7de; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }}
  th {{ background: #f6f8fa; }}
  .note {{ color: #57606a; font-size: 0.9rem; }}
  .reason {{ font-size: 0.85rem; color: #57606a; max-width: 28rem; }}
  dt {{ font-weight: 600; display: inline; }} dd {{ display: inline; margin: 0 1rem 0 0.4rem; }}
  dl {{ margin: 0.3rem 0; }}
  code {{ background: #f6f8fa; padding: 0.1rem 0.3rem; border-radius: 4px; }}
</style>
</head>
<body>
<h1>Asago run overview</h1>
<p class="note">Run <code>{e(str(summary.get('run_id')))}</code> · label
<code>{e(str(summary.get('label')))}</code> · generated {e(str(summary.get('generated_at')))}</p>
<p class="note">This overview is a derived convenience view. Native component
outputs and the decision journal are the retained evidence; a risk match is
not a finding, an admitted scenario is not an executable artifact, and an
inconclusive evaluation is not a pass. The runner does not execute business
tools; a proposed tool call is not evidence of a completed backend effect.</p>

<h2>Stage status</h2>
<table><tr><th>Stage</th><th>Status</th><th>Latest attempt</th></tr>{stage_html}</table>

<h2>Counts (separate denominators)</h2>
{funnel_html}

<h2>Evaluations</h2>
{surface_html}
<table><tr><th>Scenario</th><th>Surface</th><th>Outcome</th><th>Judge confidence</th><th>Reason</th><th>Evidence</th></tr>{eval_html}</table>

<h2>Known gaps and exclusions</h2>
<ul>{gaps_html}</ul>

<h2>Model roles</h2>
<ul>{shared_html}</ul>
{shared_note}

<h2>Evidence</h2>
<ul>{links_html}</ul>
<p class="note">Offline static page: no scripts, credentials or model calls are
needed to read it. Untrusted content (policy text, attacks, responses) is escaped.</p>
</body>
</html>
"""
    out = run.path / "reports" / "index.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(document, encoding="utf-8")
    atomic_write_json(run.path / "reports" / "summary.json", summary)
    return out
