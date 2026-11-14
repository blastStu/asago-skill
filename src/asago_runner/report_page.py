"""The offline run report: evidence collection and the HTML page.

The page is a derived convenience view of the retained evidence. Every
value it shows is read from the run's own files (native component outputs,
stage receipts, the decision journal); the runner does not invent analysis
to fill a panel. Anything untrusted — policy text, attacks, responses,
conversation transcripts — is escaped before it reaches the document.

Theme grouping uses the Policy Mapper's own curated report theme mapping
(adopted from the project's open PR #79 at a pinned commit; see the
compatibility record) joined through the SSSOM risk-to-category mapping that
the mapper already uses. Themes are a report navigation aid, not a new risk
taxonomy.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
from collections import Counter, OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from .evidence import RunDir

STAGE_SPECS = (
    {
        "key": "policy",
        "stage": "policy-mapper",
        "step": "01",
        "title": "Policy Mapper",
        "subtitle": "Policy → grounded risk evidence",
        "owner": "ASAGO COMPONENT",
    },
    {
        "key": "scenarios",
        "stage": "scenario-generator",
        "step": "02",
        "title": "Scenario Generator",
        "subtitle": "Risk evidence → adversarial scenarios",
        "owner": "ASAGO COMPONENT",
    },
    {
        "key": "artifact",
        "stage": "artifact-generator",
        "step": "03",
        "title": "Artifact Generator",
        "subtitle": "Selected scenario → Garak artifact",
        "owner": "ASAGO COMPONENT",
    },
    {
        "key": "evaluation",
        "stage": "garak",
        "step": "04",
        "title": "Garak Evaluation",
        "subtitle": "Artifact → real target response & verdict",
        "owner": "EXTERNAL: GARAK",
    },
    {
        "key": "audit",
        "stage": None,
        "step": "05",
        "title": "Run audit",
        "subtitle": "How this run was performed",
        "owner": "RUNNER + YOUR REVIEW",
    },
)

_STATUS_LABEL = {
    "completed": "Completed",
    "completed_with_gaps": "Completed with gaps",
    "needs_review": "Needs review",
    "blocked": "Blocked",
    "failed": "Failed",
    "running": "Running",
}

_THEME_ORDER = (
    "privacy",
    "fairness",
    "security",
    "reliability",
    "human-agency",
    "harmful-content",
    "intellectual-property",
    "environment",
    "other",
)
# Same policy as the mapper's evaluation join: strong, skos-prefixed
# predicates only (matching the retained SSSOM file's predicate spelling).
_STRONG_PREDICATES = {"skos:exactMatch", "skos:closeMatch", "skos:broadMatch"}
_OTHER_THEME = {
    "id": "other",
    "label": "Other / not yet grouped",
    "description": "Matches without a supported theme mapping, including custom risks.",
}


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def _read_json(path: Path | None, default: Any = None) -> Any:
    try:
        if path is not None and path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default
    return default


def _read_yaml(path: Path | None, default: Any = None) -> Any:
    try:
        if path is not None and path.is_file():
            return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return default
    return default


def _sha256(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _display_path(run: RunDir, value: str | None) -> str:
    """A path safe to show: run-relative when inside the run, else basename."""
    if not value:
        return ""
    path = Path(str(value))
    try:
        return str(path.resolve().relative_to(run.path.resolve()))
    except (ValueError, OSError):
        return path.name


def _fmt_ts(value: Any, *, with_time: bool = True) -> str:
    if not value:
        return ""
    text = str(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    return parsed.strftime("%d %b %Y, %H:%M" if with_time else "%d %b %Y")


def _duration(start: Any, end: Any) -> float | None:
    if not start or not end:
        return None
    try:
        a = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        b = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
    except ValueError:
        return None
    return round((b - a).total_seconds(), 1)


def _duration_text(seconds: float | None) -> str:
    if seconds is None:
        return ""
    if seconds < 90:
        return f"{int(seconds)}s"
    minutes, rest = divmod(int(seconds), 60)
    if minutes < 90:
        return f"{minutes}m {rest:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


def _attempt_dirs(run: RunDir, stage: str) -> list[Path]:
    root = run.path / "stages" / stage
    if not root.is_dir():
        return []
    return sorted(p for p in root.iterdir() if p.is_dir())


def _latest_attempt(run: RunDir, stage: str) -> Path | None:
    attempts = _attempt_dirs(run, stage)
    return attempts[-1] if attempts else None


def _sanitise_risk_id(risk_id: str) -> str:
    return str(risk_id).split(" ")[0].strip()


# ---------------------------------------------------------------------------
# theme mapping (adopted report navigation data, PR #79 at a pinned commit)
# ---------------------------------------------------------------------------


def _theme_definitions() -> dict[str, Any]:
    path = Path(__file__).with_name("data") / "report_themes.yaml"
    data = _read_yaml(path, {}) or {}
    themes = {t["id"]: t for t in data.get("themes", [])}
    themes.setdefault("other", _OTHER_THEME)
    return {
        "themes": themes,
        "categories": data.get("category_taxonomies", {}),
        "version": data.get("version"),
    }


def _sssom_path(run: RunDir) -> Path | None:
    retained = run.path / "originals" / "sssom" / "risk_to_category.sssom.tsv"
    if retained.is_file():
        return retained
    try:
        import asago_policy_mapper

        packaged = (
            Path(asago_policy_mapper.__file__).parent
            / "data"
            / "risk_to_category.sssom.tsv"
        )
        if packaged.is_file():
            return packaged
    except (ImportError, OSError):
        return None
    return None


def _load_risk_categories(path: Path | None) -> dict[str, dict[str, set[str]]]:
    mapping: dict[str, dict[str, set[str]]] = {}
    if path is None or not path.is_file():
        return mapping
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip() or line.startswith("#") or line.startswith("subject_id"):
            continue
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 5:
            continue
        subject, _subject_src, predicate, obj, obj_src = parts[:5]
        if predicate not in _STRONG_PREDICATES:
            continue
        mapping.setdefault(subject, {}).setdefault(obj_src.strip(), set()).add(obj)
    return mapping


def _theme_join(
    risk_id: str,
    risk_categories: dict[str, dict[str, set[str]]],
    definitions: dict[str, Any],
) -> tuple[list[str], list[dict[str, str]]]:
    """Theme ids plus the category links that produced them (report only)."""
    rid = _sanitise_risk_id(risk_id)
    found: set[str] = set()
    links: list[dict[str, str]] = []
    for taxonomy, category_ids in sorted(risk_categories.get(rid, {}).items()):
        framework = definitions["categories"].get(taxonomy, {})
        for category_id in sorted(category_ids):
            category = framework.get("categories", {}).get(category_id)
            if not category:
                continue
            found.update(category.get("themes", []))
            links.append(
                {
                    "taxonomy": taxonomy,
                    "taxonomy_label": framework.get("label", taxonomy),
                    "category": category.get("label", category_id),
                }
            )
    ordered = [theme for theme in _THEME_ORDER if theme in found]
    return (ordered or ["other"]), links


def _themes_for(
    risk_id: str,
    risk_categories: dict[str, dict[str, set[str]]],
    definitions: dict[str, Any],
) -> list[str]:
    return _theme_join(risk_id, risk_categories, definitions)[0]


# ---------------------------------------------------------------------------
# collection
# ---------------------------------------------------------------------------


def _collect_policy(run: RunDir, manifest: dict) -> dict[str, Any]:
    extraction_path = None
    rel = (manifest.get("flow", {}).get("mapper_output") or {}).get("extraction")
    if rel and (run.path / rel).is_file():
        extraction_path = run.path / rel
    else:
        for attempt in reversed(_attempt_dirs(run, "policy-mapper")):
            candidate = attempt / "risk-extraction.json"
            if candidate.is_file():
                extraction_path = candidate
                break
    data = _read_json(extraction_path, {}) or {}
    risks_raw = data.get("risks") or []
    definitions = _theme_definitions()
    sssom = _sssom_path(run)
    risk_categories = _load_risk_categories(sssom)

    risks: list[dict[str, Any]] = []
    for risk in risks_raw:
        theme_ids, theme_links = _theme_join(
            risk.get("risk_id", ""), risk_categories, definitions
        )
        evidence = []
        for item in (risk.get("evidence") or [])[:8]:
            if not isinstance(item, dict):
                continue
            evidence.append(
                {
                    "text": item.get("text") or "",
                    "document": _display_path(run, item.get("document")),
                    "section": item.get("section"),
                    "page": item.get("page"),
                }
            )
        mitigations = [
            m.get("mitigation_id") or m.get("name") or m.get("title") or str(m)
            for m in (risk.get("mitigations") or [])
            if isinstance(m, dict)
        ]
        risks.append(
            {
                "risk_id": risk.get("risk_id"),
                "risk_name": risk.get("risk_name"),
                "risk_description": risk.get("risk_description"),
                "taxonomy": risk.get("taxonomy") or "unknown",
                "grounding_confidence": (risk.get("grounding_confidence") or "unknown").lower(),
                "accepted_by": risk.get("accepted_by"),
                "theme_ids": theme_ids,
                "theme_links": theme_links,
                "evidence": evidence,
                "threat": risk.get("threat"),
                "vulnerability": risk.get("vulnerability"),
                "consequence": risk.get("consequence"),
                "impact": risk.get("impact"),
                "mitigations": mitigations,
            }
        )

    taxonomy_counts = Counter(r["taxonomy"] or "unknown" for r in risks)
    grounding_counts = Counter(r["grounding_confidence"] for r in risks)
    review_suggested = sum(
        count
        for level, count in grounding_counts.items()
        if level in ("medium", "low", "ungrounded")
    )
    theme_counts: Counter[str] = Counter()
    for risk in risks:
        theme_counts.update(risk["theme_ids"])
    theme_labels = {
        theme_id: definitions["themes"].get(theme_id, _OTHER_THEME)["label"]
        for theme_id in _THEME_ORDER
        if theme_counts.get(theme_id)
    }
    return {
        "extraction": run.rel(extraction_path) if extraction_path else None,
        "risks": risks,
        "counts": {
            "total": len(risks),
            "taxonomies": dict(
                sorted(taxonomy_counts.items(), key=lambda item: (-item[1], item[0]))
            ),
            "grounding": {
                level: grounding_counts.get(level, 0)
                for level in ("high", "medium", "low", "ungrounded")
            },
            "review_suggested": review_suggested,
            "themes": {
                theme_id: theme_counts[theme_id]
                for theme_id in _THEME_ORDER
                if theme_counts.get(theme_id)
            },
        },
        "theme_labels": theme_labels,
        "theme_mapping": {
            "version": definitions["version"],
            "sssom": _display_path(run, str(sssom)) if sssom else None,
            "sssom_sha256": _sha256(sssom) if sssom else None,
            "provenance": (
                "curated Asago report navigation from asago-ai/asago-policy-mapper "
                "PR #79 at d2423c7bf12432f44fab6963f497dc7f975c7c26 (open, "
                "unmerged when adopted); joined through the mapper's own "
                "exact/close/broad SSSOM mappings"
            ),
        },
        "source_documents": [
            _display_path(run, doc) for doc in (data.get("source_documents") or [])
        ],
        "accounting": data.get("token_usage") or {},
    }


def _scenario_attempt(run: RunDir, manifest: dict) -> Path | None:
    receipts = (manifest.get("flow", {}).get("scenario_handoff") or {}).get("receipts")
    if receipts:
        candidate = run.path / receipts
        if candidate.parent.parent.name.startswith("000"):
            return candidate.parent.parent
    for attempt in reversed(_attempt_dirs(run, "scenario-generator")):
        if any((attempt / "handoff").glob("*.yaml")):
            return attempt
    return None


def _scenario_surface(scenario: dict, surface_by_scenario: dict[str, str]) -> tuple[str, str]:
    scenario_id = scenario.get("scenario_id")
    if scenario_id in surface_by_scenario:
        return surface_by_scenario[scenario_id], "from the reviewed replay entry"
    snapshot = (scenario.get("projection") or {}).get("capability_snapshot") or {}
    entry_point_id = (scenario.get("projection") or {}).get("canonical_ingress", {}).get(
        "entry_point_id"
    )
    for entry in snapshot.get("profile", {}).get("entry_points", []) or []:
        if entry.get("entry_point_id") != entry_point_id:
            continue
        kind = entry.get("entry_point_type")
        if kind == "user_input":
            return "user_turn", "derived from the projected entry point"
        if kind in ("external_content", "tool_output", "tool_result"):
            return "tool_return", "derived from the projected entry point"
    return "unknown", "not represented in a replay entry"


def _collect_scenarios(
    run: RunDir,
    manifest: dict,
    policy_by_id: dict[str, dict],
    surface_by_scenario: dict[str, str],
) -> dict[str, Any]:
    attempt_dir = _scenario_attempt(run, manifest)
    scenarios: list[dict[str, Any]] = []
    if attempt_dir:
        for yaml_path in sorted((attempt_dir / "handoff").glob("*.yaml")):
            scenario = _read_yaml(yaml_path, {}) or {}
            if not isinstance(scenario, dict):
                continue
            narrative = scenario.get("narrative") or {}
            seed = scenario.get("scenario_seed_metadata") or {}
            risk_card = (scenario.get("faceting") or {}).get("risk_card") or {}
            risk = policy_by_id.get(risk_card.get("risk_id")) or {}
            surface, surface_basis = _scenario_surface(scenario, surface_by_scenario)
            behavior = scenario.get("behavior_spec") or {}
            scenarios.append(
                {
                    "scenario_id": scenario.get("scenario_id"),
                    "title": narrative.get("title") or risk_card.get("risk_name") or "Scenario",
                    "summary": narrative.get("summary") or "",
                    "entry_point": narrative.get("entry_point") or "",
                    "seed_id": seed.get("seed_id"),
                    "threat_name": seed.get("threat_name"),
                    "attack_pattern_name": seed.get("attack_pattern_name"),
                    "atlas_techniques": seed.get("atlas_technique_ids") or [],
                    "owasp_origin": seed.get("owasp_origin"),
                    "risk": {
                        "risk_id": risk_card.get("risk_id"),
                        "risk_name": risk_card.get("risk_name"),
                        "taxonomy": risk_card.get("taxonomy"),
                        "grounding_confidence": risk_card.get("grounding_confidence"),
                        "evidence_quote": (risk.get("evidence") or [{}])[0].get("text", "")
                        if risk.get("evidence")
                        else "",
                    },
                    "surface": surface,
                    "surface_basis": surface_basis,
                    "steps": [
                        {
                            "step_number": step.get("step_number"),
                            "zone": step.get("zone"),
                            "action": step.get("action"),
                            "effect": step.get("effect"),
                        }
                        for step in (narrative.get("steps") or [])
                    ],
                    "behavior_gherkin": behavior.get("gherkin_text") or "",
                    "yaml": run.rel(yaml_path),
                    "feature": run.rel(yaml_path.with_suffix(".feature"))
                    if yaml_path.with_suffix(".feature").is_file()
                    else None,
                }
            )
    inventory = {}
    # The attempt record carries the native inventory summary.
    for record in (manifest.get("stages", {}).get("scenario-generator", {}) or {}).get(
        "attempts", []
    ):
        if record.get("inventory_summary"):
            inventory = record["inventory_summary"]
    surfaces = Counter(s["surface"] for s in scenarios)
    traceable = sum(1 for s in scenarios if s["risk"]["risk_id"])
    return {
        "attempt": run.rel(attempt_dir) if attempt_dir else None,
        "scenarios": scenarios,
        "counts": {
            "admitted": inventory.get("admitted", len(scenarios)),
            "quarantined": inventory.get("quarantined", 0),
            "writable": len(surface_by_scenario),
            "surfaces": dict(surfaces),
            "linked_to_risk": traceable,
            "no_risk_id": len(scenarios) - traceable,
        },
    }


def _artifact_attempt(run: RunDir, manifest: dict) -> Path | None:
    rel = (manifest.get("flow", {}).get("replay_entries") or {}).get("attempt")
    if rel and (run.path / rel).is_dir():
        return run.path / rel
    for attempt in reversed(_attempt_dirs(run, "artifact-generator")):
        if (attempt / "replay-entries").is_dir():
            return attempt
    return None


def _collect_artifacts(run: RunDir, manifest: dict) -> dict[str, Any]:
    attempt_dir = _artifact_attempt(run, manifest)
    entries: list[dict[str, Any]] = []
    surfaces: dict[str, str] = {}
    if attempt_dir:
        for entry_path in sorted((attempt_dir / "replay-entries").glob("*.replay-entry.json")):
            scenario_id = entry_path.name[: -len(".replay-entry.json")]
            entry = _read_json(entry_path, {}) or {}
            meta_path = entry_path.with_name(
                entry_path.name.replace(".replay-entry.json", ".replay-meta.json")
            )
            meta = _read_json(meta_path, {}) or {}
            surfaces[scenario_id] = meta.get("surface") or "unknown"
            # The parent Garak artifact and its validation record are
            # reconstructed under the attempt's native run directory; the
            # stored absolute path may predate a move of the run.
            parent = None
            parent_sha = (meta.get("parent_artifact") or {}).get("sha256")
            for candidate in (attempt_dir / "runs" / scenario_id).glob("*-garak.json"):
                if parent_sha is None or _sha256(candidate) == parent_sha:
                    parent = _read_json(candidate, {}) or {}
                    break
            validation = _read_json(
                attempt_dir / "runs" / scenario_id / "validation.json", {}
            ) or {}
            turns = []
            for index, message in enumerate(entry.get("messages") or []):
                turns.append(
                    {
                        "index": index,
                        "role": message.get("role"),
                        "content": message.get("content") or "",
                        "name": message.get("name"),
                        "tool_call_id": message.get("tool_call_id"),
                        "tool_calls": message.get("tool_calls") or [],
                    }
                )
            entries.append(
                {
                    "scenario_id": scenario_id,
                    "surface": meta.get("surface") or "unknown",
                    "surface_reason": meta.get("surface_reason") or "",
                    "attack_turn_index": meta.get("attack_turn_index"),
                    "tools": entry.get("tools") or [],
                    "judge_description": entry.get("judge_description"),
                    "messages": turns,
                    "schema_sources": meta.get("schema_sources") or [],
                    "parent_artifact": _display_path(
                        run, (meta.get("parent_artifact") or {}).get("path")
                    ),
                    "platform_coverage": (parent or {}).get("platform_coverage"),
                    "artifact_model": (parent or {}).get("model"),
                    "rubric": (parent or {}).get("detector_rubric") or {},
                    "validation": {
                        "ok": validation.get("ok"),
                        "errors": validation.get("errors") or [],
                        "checks": validation.get("checks"),
                    },
                    "entry": run.rel(entry_path),
                    "meta": run.rel(meta_path) if meta_path.is_file() else None,
                }
            )
    validation_ok = all(e["validation"]["ok"] for e in entries) if entries else None
    return {
        "attempt": run.rel(attempt_dir) if attempt_dir else None,
        "entries": entries,
        "surfaces": surfaces,
        "counts": {
            "entries": len(entries),
            "validation_ok": validation_ok,
            "turns": len(entries[0]["messages"]) if entries else 0,
            "platform_coverage": entries[0]["platform_coverage"] if entries else None,
        },
    }


def _collect_evaluations(
    run: RunDir, manifest: dict, artifacts: dict[str, Any]
) -> dict[str, Any]:
    latest: dict[str, dict[str, Any]] = {}
    for record in (manifest.get("stages", {}).get("garak", {}) or {}).get(
        "attempts", []
    ):
        for dispatch in record.get("dispatches", []) or []:
            dispatch_dir = dispatch.get("dispatch_dir")
            outcome = _read_json(run.path / dispatch_dir / "outcome.json", {}) if dispatch_dir else {}
            scenario_id = dispatch.get("scenario_id") or outcome.get("scenario_id")
            if not scenario_id:
                continue
            latest[scenario_id] = {
                "scenario_id": scenario_id,
                "outcome": dispatch.get("outcome") or outcome.get("outcome"),
                "reason": dispatch.get("reason") or outcome.get("reason"),
                "judge_confidence": dispatch.get("judge_confidence"),
                "detector_score": dispatch.get("detector_score"),
                "surface": dispatch.get("surface") or outcome.get("surface"),
                "target_model": outcome.get("target_model"),
                "judge_model": outcome.get("judge_model"),
                "confidence_cutoff": outcome.get("confidence_cutoff"),
                "detector": outcome.get("detector"),
                "attempts": outcome.get("attempts") or [],
                "dispatch_dir": dispatch_dir,
                "timing": outcome.get("timing") or {},
            }
    rubric_by_scenario = {
        entry["scenario_id"]: entry["rubric"] for entry in artifacts.get("entries", [])
    }
    target_by_scenario = {
        entry["scenario_id"]: entry
        for entry in artifacts.get("entries", [])
    }
    evaluations = []
    for scenario_id, evaluation in latest.items():
        evaluation = dict(evaluation)
        evaluation["rubric"] = rubric_by_scenario.get(scenario_id) or {}
        evaluation["artifact"] = target_by_scenario.get(scenario_id)
        evaluations.append(evaluation)
    outcomes = Counter(e["outcome"] for e in evaluations)
    return {"evaluations": evaluations, "counts": dict(outcomes)}


def _collect_audit(run: RunDir, manifest: dict) -> dict[str, Any]:
    decisions = []
    journal = run.path / "decisions.jsonl"
    if journal.is_file():
        for line in journal.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            decisions.append(
                {
                    "id": record.get("id"),
                    "recorded_at": record.get("recorded_at"),
                    "category": record.get("category"),
                    "actor": (record.get("actor") or {}).get("label")
                    or (record.get("actor") or {}).get("identity_source")
                    or "unrecorded",
                    "question": record.get("question"),
                    "response": record.get("response"),
                    "resolution": record.get("resolution"),
                    "state": record.get("state"),
                    "notes": record.get("visible_notes"),
                }
            )
    attempts = []
    for stage, record in (manifest.get("stages") or {}).items():
        for attempt in record.get("attempts", []) or []:
            attempt_dir = run.path / (attempt.get("attempt_dir") or "")
            model = _read_json(attempt_dir / "model-identity.json", {}) or {}
            counts = {}
            accounting = attempt.get("accounting") or {}
            if accounting:
                counts["risks"] = accounting.get("risks_total")
                counts["downstream-supported"] = accounting.get("risks_downstream_supported")
            inventory = attempt.get("inventory_summary") or {}
            if inventory:
                counts["admitted"] = inventory.get("admitted")
                counts["quarantined"] = inventory.get("quarantined")
            if attempt.get("dispatches"):
                counts["evaluations"] = len(attempt["dispatches"])
            attempts.append(
                {
                    "stage": stage,
                    "attempt_id": attempt.get("attempt_id"),
                    "status": attempt.get("status"),
                    "started_at": attempt.get("started_at"),
                    "completed_at": attempt.get("completed_at"),
                    "duration_seconds": _duration(
                        attempt.get("started_at"), attempt.get("completed_at")
                    ),
                    "model": model.get("model"),
                    "command": attempt.get("command"),
                    "counts": counts,
                    "error": attempt.get("error") or attempt.get("error_detail"),
                    "blockers": attempt.get("blockers") or [],
                    "gaps": attempt.get("gaps") or [],
                }
            )
    reviews = []
    reviews_dir = run.path / "reviews"
    if reviews_dir.is_dir():
        for path in sorted(reviews_dir.glob("*.json")):
            reviews.append(
                {
                    "path": run.rel(path),
                    "name": path.name,
                    "kind": path.name.split(".")[0],
                    "role": "request" if ".request." in path.name else "response",
                }
            )
    config = manifest.get("config_snapshot") or {}
    models = []
    for role, spec in (config.get("connections") or {}).items():
        models.append(
            {
                "role": role,
                "model": spec.get("model") or "not recorded",
                "host": spec.get("base_url_host"),
                "shared": any(
                    role in group for group in config.get("shared_model_roles") or []
                ),
            }
        )
    return {
        "decisions": decisions,
        "attempts": attempts,
        "reviews": reviews,
        "models": models,
        "scope": config.get("scope") or {},
        "subject": manifest.get("subject", "built"),
        "created_at": manifest.get("created_at"),
        "config_sha256": config.get("config_sha256"),
        "policy_documents": config.get("policy_documents") or [],
        "system_name": (
            (config.get("raw_non_secret") or {}).get("system", {}).get("identity", {})
            or {}
        ).get("system_name"),
        "system_boundary": (
            (config.get("raw_non_secret") or {}).get("system", {}).get("identity", {})
            or {}
        ).get("boundary"),
    }


def collect_report_data(run: RunDir, summary: dict) -> dict[str, Any]:
    """Read the derived report detail from the retained evidence tree."""
    manifest = run.manifest()
    policy = _collect_policy(run, manifest)
    policy_by_id = {r["risk_id"]: r for r in policy["risks"] if r.get("risk_id")}
    artifacts = _collect_artifacts(run, manifest)
    scenarios = _collect_scenarios(
        run, manifest, policy_by_id, artifacts["surfaces"]
    )
    evaluations = _collect_evaluations(run, manifest, artifacts)
    audit = _collect_audit(run, manifest)
    return {
        "policy": policy,
        "scenarios": scenarios,
        "artifacts": artifacts,
        "evaluations": evaluations,
        "audit": audit,
    }


# ---------------------------------------------------------------------------
# stage state
# ---------------------------------------------------------------------------


def stage_states(summary: dict, data: dict) -> list[dict[str, Any]]:
    """One card per stage, including the reason a stage was not run."""
    subject = summary.get("subject", "built")
    stages = summary.get("stages") or {}
    states = []
    for spec in STAGE_SPECS:
        state = {
            "key": spec["key"],
            "step": spec["step"],
            "title": spec["title"],
            "subtitle": spec["subtitle"],
            "owner": spec["owner"],
            "status": "not-run",
            "label": "Not run",
            "reason": "",
        }
        if spec["key"] == "audit":
            state["status"] = "completed"
            state["label"] = "Recorded"
            states.append(state)
            continue
        record = stages.get(spec["stage"]) or {}
        status = record.get("status")
        if status:
            state["status"] = status
            state["label"] = _STATUS_LABEL.get(status, status.replace("_", " "))
            states.append(state)
            continue
        if subject == "proposed" and spec["stage"] in (
            "artifact-generator",
            "garak",
        ):
            state["label"] = "Not run — design-time"
            state["reason"] = (
                "The subject is a proposed design; there is nothing to attack yet. "
                "Artifacts and evaluation are possible only once the system is built."
            )
        else:
            state["label"] = "Not reached"
            state["reason"] = (
                "The run did not reach this stage. See the run audit for the "
                "recorded outcome and the decision that stopped or changed it."
            )
        states.append(state)
    return states


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _pct(part: int, total: int) -> float:
    return (100.0 * part / total) if total else 0.0


def _theme_chip(theme_id: str, labels: dict[str, str]) -> str:
    return (
        f"<span class='chip theme-{_esc(theme_id)}'>"
        f"{_esc(labels.get(theme_id, theme_id))}</span>"
    )


def _grounding_badge(level: str) -> str:
    level = (level or "unknown").lower()
    return f"<span class='badge grounding-{_esc(level)}'>{_esc(level.title())}</span>"


def _bar_rows(
    counts: dict[str, int],
    labels: dict[str, str],
    *,
    filter_kind: str,
    colours: dict[str, str] | None = None,
) -> str:
    total = max(counts.values(), default=0) or 1
    rows = []
    for key, count in counts.items():
        label = labels.get(key, key)
        colour = (colours or {}).get(key)
        style = f"background:{_esc(colour)}" if colour else ""
        rows.append(
            "<button type='button' class='bar-button' "
            f"data-filter-kind='{_esc(filter_kind)}' data-filter-value='{_esc(key)}'>"
            f"<span class='bar-label'>{_esc(label)}</span>"
            f"<span class='bar-track'><b style='width:{_pct(count, total):.1f}%;{style}'></b></span>"
            f"<strong>{count}</strong></button>"
        )
    return "".join(rows)


def _metric(value: Any, label: str, *, variant: str = "", title: str = "") -> str:
    return (
        f"<div class='metric {_esc(variant)}' title='{_esc(title)}'>"
        f"<strong>{_esc(value)}</strong><span>{_esc(label)}</span></div>"
    )


def _panel_head(spec: dict, state: dict, *, extra: str = "") -> str:
    status = state.get("status", "")
    return (
        "<header class='result-heading'>"
        "<div>"
        f"<p class='eyebrow'>{_esc(spec['step'])} / {_esc(spec['title'].upper())}</p>"
        f"<h2>{_esc(spec['title'])}</h2>"
        f"<p class='panel-description'>{_esc(spec['subtitle'])}</p>"
        "<p class='owner-tag'>Whose work: "
        f"<strong>[{_esc(spec['owner'])}]</strong></p>"
        "</div>"
        f"<div class='result-actions'><span class='status-pill status-{_esc(status)}'>"
        f"{_esc(state.get('label'))}</span>{extra}</div>"
        "</header>"
    )


def _render_policy(data: dict) -> str:
    policy = data["policy"]
    counts = policy["counts"]
    risks = policy["risks"]
    if not risks:
        return (
            "<div class='results-inner'><p class='empty'>No risk matches are "
            "recorded in this run. The Policy Mapper produced no grounded "
            "extraction, so there is nothing to report for this stage.</p></div>"
        )
    labels = policy["theme_labels"]
    labels = {**{k: v for k, v in labels.items()}, "other": "Other / not yet grouped"}
    theme_colours = {
        "privacy": "#5b8def",
        "fairness": "#c77dff",
        "security": "#0dd4a0",
        "reliability": "#7eb0ff",
        "human-agency": "#f5b84d",
        "harmful-content": "#f2705b",
        "intellectual-property": "#57c7d4",
        "environment": "#8fce6f",
        "other": "#94a3b8",
    }
    taxonomy_labels = {
        taxonomy: taxonomy
        for taxonomy in counts["taxonomies"]
    }
    grounding = counts["grounding"]
    grounding_total = sum(grounding.values()) or 1
    grounding_segments = []
    for level, colour in (
        ("high", "#0dd4a0"),
        ("medium", "#f5b84d"),
        ("low", "#ed865e"),
        ("ungrounded", "#94a3b8"),
    ):
        count = grounding.get(level, 0)
        if count:
            grounding_segments.append(
                f"<div class='grounding-segment' style='width:{_pct(count, grounding_total):.1f}%;"
                f"background:{colour}' title='{_esc(level)}: {count}'>"
                f"{count if _pct(count, grounding_total) > 8 else ''}</div>"
            )
    grounding_html = (
        "<div class='grounding-bar'>" + "".join(grounding_segments) + "</div>"
        "<div class='grounding-legend'>"
        + "".join(
            f"<span><i style='background:{colour}'></i>{_esc(level.title())} "
            f"<strong>{grounding.get(level, 0)}</strong> "
            f"<small>{_pct(grounding.get(level, 0), grounding_total):.1f}%</small></span>"
            for level, colour in (
                ("high", "#0dd4a0"),
                ("medium", "#f5b84d"),
                ("low", "#ed865e"),
                ("ungrounded", "#94a3b8"),
            )
        )
        + "</div>"
    )

    rows = []
    for risk in risks:
        theme_ids = risk["theme_ids"]
        search = " ".join(
            str(risk.get(key) or "")
            for key in ("risk_id", "risk_name", "taxonomy", "risk_description")
        )
        evidence_html = ""
        for item in risk["evidence"]:
            location = " · ".join(
                part
                for part in (
                    item.get("section"),
                    item.get("document"),
                    f"page {item['page']}" if item.get("page") else "",
                )
                if part
            )
            evidence_html += (
                "<blockquote class='policy-quote'>"
                f"<p>{_esc(item.get('text'))}</p>"
                f"<cite>{_esc(location)}</cite></blockquote>"
            )
        detail_bits = []
        for label, key in (
            ("Threat", "threat"),
            ("Vulnerability", "vulnerability"),
            ("Consequence", "consequence"),
            ("Impact", "impact"),
        ):
            if risk.get(key):
                detail_bits.append(
                    f"<p><strong>{label}.</strong> {_esc(risk[key])}</p>"
                )
        mitigations = ""
        if risk["mitigations"]:
            mitigations = (
                "<p><strong>Mitigations linked by the mapper.</strong> "
                + _esc(", ".join(str(m) for m in risk["mitigations"]))
                + "</p>"
            )
        rows.append(
            "<article class='finding' data-theme='{themes}' data-taxonomy='{tax}' "
            "data-grounding='{ground}' data-search='{search}'>"
            "<details><summary>"
            "<span class='finding-main'><span class='finding-name'>{name}</span>"
            "<span class='chips'>{chips}</span></span>"
            "<span class='finding-meta'>"
            "<span class='taxonomy-badge'>{tax}</span>"
            "{grounding}"
            "<span class='evidence-count'>{n} passage{s}</span>"
            "</span></summary>"
            "<div class='finding-body'>"
            "<p class='finding-id'>{rid}</p>"
            "{description}{theme_basis}{details}{mitigations}"
            "<h4>Supporting policy passages</h4>{evidence}"
            "<p class='fineprint'>A grounded risk match is evidence of relevance "
            "in the policy text, not a finding about the system. Counts use the "
            "Policy Mapper's own matched-entry denominator.</p>"
            "</div></details></article>".format(
                themes=_esc(" ".join(theme_ids)),
                tax=_esc(risk["taxonomy"]),
                ground=_esc(risk["grounding_confidence"]),
                search=_esc(search),
                name=_esc(risk["risk_name"]),
                chips="".join(_theme_chip(t, labels) for t in theme_ids),
                grounding=_grounding_badge(risk["grounding_confidence"]),
                n=len(risk["evidence"]),
                s="" if len(risk["evidence"]) == 1 else "s",
                rid=_esc(risk["risk_id"]),
                description=(
                    f"<p>{_esc(risk['risk_description'])}</p>"
                    if risk.get("risk_description")
                    else ""
                ),
                theme_basis=(
                    "<p class='fineprint'><strong>Theme basis.</strong> "
                    + _esc(
                        "; ".join(
                            f"{link['taxonomy_label']}: {link['category']}"
                            for link in risk["theme_links"][:8]
                        )
                    )
                    + "</p>"
                    if risk["theme_links"]
                    else "<p class='fineprint'><strong>Theme basis.</strong> No strong "
                    "SSSOM category mapping; shown as other.</p>"
                ),
                details="".join(detail_bits),
                mitigations=mitigations,
                evidence=evidence_html or "<p class='fineprint'>No passage retained.</p>",
            )
        )

    return f"""
<div class="results-inner">
  <div class="metrics">
    {_metric(counts['total'], 'Risk matches', title='Grounded taxonomy entries matched by the Policy Mapper in this run.')}
    {_metric(len(counts['taxonomies']), 'Taxonomies represented', title='Frameworks with at least one matched entry.')}
    {_metric(grounding.get('high', 0), 'High grounding confidence', variant='mint', title='Matches with strong supporting passage evidence.')}
    {_metric(counts['review_suggested'], 'Review suggested', variant='amber', title='Medium, low or ungrounded matches worth reading before relying on them.')}
  </div>
  <p class="metric-note">A risk may have matches in several taxonomies; counts describe
  matched entries in those taxonomies, not distinct policy topics.</p>
  <div class="charts">
    <section class="chart"><h3>Risk matches by theme</h3>
      {_bar_rows(counts['themes'], {**labels, 'other': 'Other / not yet grouped'}, filter_kind='theme')}
      <p class="fineprint">Curated Asago report navigation, not a new risk taxonomy. A risk can
      belong to more than one theme.</p>
    </section>
    <section class="chart"><h3>Risk matches by taxonomy</h3>
      {_bar_rows(counts['taxonomies'], taxonomy_labels, filter_kind='taxonomy')}
    </section>
    <section class="chart"><h3>Grounding confidence</h3>
      {grounding_html}
      <p class="fineprint">Grounding confidence reflects the strength of the supporting
      passage, not the severity of the risk.</p>
    </section>
  </div>
  <div class="findings-heading">
    <div><p class="eyebrow">EXPLORE FINDINGS</p>
    <h3>Open a risk to read the supporting policy passages and risk context.</h3></div>
    <span id="finding-count" class="muted">{counts['total']} of {counts['total']} matches</span>
  </div>
  <div class="filter-row">
    <label>Theme
      <select data-filter="theme"><option value="">All</option>
      {"".join(f"<option value='{_esc(k)}'>{_esc(v)}</option>" for k, v in {**labels, 'other': 'Other / not yet grouped'}.items())}
      </select></label>
    <label>Grounding
      <select data-filter="grounding"><option value="">All</option>
      <option value="review">Review suggested</option>
      <option value="high">High</option><option value="medium">Medium</option>
      <option value="low">Low</option><option value="ungrounded">Ungrounded</option>
      </select></label>
    <label>Taxonomy
      <select data-filter="taxonomy"><option value="">All</option>
      {"".join(f"<option value='{_esc(k)}'>{_esc(k)}</option>" for k in counts['taxonomies'])}
      </select></label>
    <label class="search-label">Search
      <input type="search" id="risk-search" placeholder="Risk name or ID…">
    </label>
    <button type="button" id="reset-filters" class="quiet">Reset filters</button>
  </div>
  <div class="findings" id="findings">
    {"".join(rows)}
  </div>
  <p class="fineprint">{_esc(policy['theme_mapping']['provenance'])}. Theme mapping
  version {_esc(policy['theme_mapping']['version'])}; SSSOM
  {_esc(policy['theme_mapping']['sssom'] or 'not available')}.
  {'Extraction: <a href="../' + _esc(policy['extraction']) + '">native risk-extraction.json</a>.' if policy.get('extraction') else ''}</p>
</div>
"""


def _render_scenarios(data: dict) -> str:
    scenarios = data["scenarios"]
    counts = scenarios["counts"]
    items = scenarios["scenarios"]
    if not items:
        return (
            "<div class='results-inner'><p class='empty'>No admitted scenarios "
            "are recorded. See the stage outcome and the run audit for the "
            "native inventory and any quarantine reasons.</p></div>"
        )
    surface_labels = {"user_turn": "USER_TURN", "tool_return": "TOOL_RETURN", "unknown": "UNKNOWN"}
    cards = []
    for scenario in items:
        risk = scenario["risk"]
        trace = ""
        if risk.get("risk_id"):
            trace = (
                "<div class='trace'><p class='eyebrow'>POLICY TRACE · "
                f"{_esc(risk['risk_id'])}</p>"
                f"<p>{_esc(risk.get('risk_name'))}</p>"
                + (
                    f"<blockquote class='policy-quote'><p>{_esc(risk['evidence_quote'])}</p></blockquote>"
                    if risk.get("evidence_quote")
                    else ""
                )
                + "</div>"
            )
        steps = ""
        if scenario["steps"]:
            steps = (
                "<h4>Projected attack steps</h4><ol class='steps'>"
                + "".join(
                    f"<li><span class='zone'>{_esc(step.get('zone'))}</span> "
                    f"{_esc(step.get('action'))}</li>"
                    for step in scenario["steps"]
                )
                + "</ol>"
            )
        behavior = (
            f"<h4>Behavior specification</h4><pre class='code'>{_esc(scenario['behavior_gherkin'])}</pre>"
            if scenario["behavior_gherkin"]
            else ""
        )
        cards.append(
            f"<article class='scenario-card' data-surface='{_esc(scenario['surface'])}'>"
            "<div class='scenario-top'><div class='scenario-copy'>"
            f"<span class='mono id'>{_esc(scenario['scenario_id'])}</span>"
            f"<h3>{_esc(scenario['title'])}</h3></div>"
            f"<span class='surface-tag surface-{_esc(scenario['surface'])}'>"
            f"{_esc(surface_labels.get(scenario['surface'], scenario['surface']))}</span></div>"
            "<details><summary>Scenario, policy evidence &amp; behavior</summary>"
            "<div class='scenario-body'>"
            f"<p>{_esc(scenario['summary'])}</p>"
            "<p class='fineprint'>Entry point: {ep} · Surface: {surface} ({basis})"
            " · Seed: {seed}</p>"
            "{trace}{steps}{behavior}"
            "<h4>Native evidence</h4><p class='links'>"
            "<a href='../{yaml}'>scenario YAML</a>"
            "{feature}</p>"
            "</div></details></article>".format(
                ep=_esc(scenario["entry_point"] or "not recorded"),
                surface=_esc(scenario["surface"]),
                basis=_esc(scenario["surface_basis"]),
                seed=_esc(scenario["seed_id"] or "not recorded"),
                trace=trace,
                steps=steps,
                behavior=behavior,
                yaml=_esc(scenario["yaml"]),
                feature=(
                    f" · <a href='../{_esc(scenario['feature'])}'>behavior feature</a>"
                    if scenario.get("feature")
                    else ""
                ),
            )
        )
    surface_counts = counts["surfaces"]
    return f"""
<div class="results-inner">
  <div class="metrics">
    {_metric(counts['admitted'], 'Admitted scenarios', title='Admitted by the Scenario Generator’s native finalization inventory.')}
    {_metric(counts['quarantined'], 'Rejected / quarantined', title='Candidates that did not pass native qualification or validation.')}
    {_metric(counts['writable'], 'Scenarios writable in Garak', variant='mint', title='Admitted scenarios with a replay entry the runner could build.')}
  </div>
  <div class="charts">
    <section class="chart"><h3>Injection surfaces · select to filter</h3>
      {_bar_rows(surface_counts, {k: v.replace('_', ' ') for k, v in surface_labels.items()}, filter_kind='surface')}
      <p class="fineprint">The surface shown is the one recorded in the reviewed replay entry,
      or derived from the projection when no entry exists.</p>
    </section>
    <section class="chart"><h3>Policy risk traceability</h3>
      <div class="traceability">
        <div><strong>{counts['linked_to_risk']}</strong><span>Linked to a matched risk</span></div>
        <div><strong>{counts['no_risk_id']}</strong><span>No risk ID exported</span></div>
      </div>
      <p class="fineprint">Traceability comes from the scenario’s own risk card. A scenario
      without a risk ID is still a valid adversarial scenario; it simply has no policy trace.</p>
    </section>
  </div>
  <div class="findings-heading">
    <div><p class="eyebrow">ADMITTED SCENARIOS</p>
    <h3>Adversarial scenarios and their policy evidence.</h3></div>
    <span class="muted">{len(items)} shown</span>
  </div>
  <div class="scenario-options">
    <label>Surface
      <select id="surface-filter"><option value="">All injection surfaces</option>
      {"".join(f"<option value='{_esc(k)}'>{_esc(v.replace('_',' '))}</option>" for k, v in surface_labels.items() if k in surface_counts)}
      </select></label>
  </div>
  <div class="scenario-list">{"".join(cards)}</div>
  <p class="fineprint">{_esc(scenarios['attempt'] or 'No scenario attempt recorded')}. An admitted
  scenario is not yet an executable artifact; stage 03 records what could be replayed.</p>
</div>
"""


def _render_artifact(data: dict) -> str:
    artifacts = data["artifacts"]
    entries = artifacts["entries"]
    if not entries:
        return (
            "<div class='results-inner'><p class='empty'>No replay entries were "
            "built in this run. See the run audit for the stage outcome.</p></div>"
        )
    counts = artifacts["counts"]
    coverage = counts["platform_coverage"]
    validation = "Passed" if counts["validation_ok"] else "Issues recorded"
    entry_blocks = []
    for entry in entries:
        turns = []
        for turn in entry["messages"]:
            attack = entry["attack_turn_index"] == turn["index"]
            tool_calls = ""
            if turn["tool_calls"]:
                tool_calls = (
                    "<p class='mono-label'>Proposed tool calls</p>"
                    f"<pre class='code'>{_esc(json.dumps(turn['tool_calls'], indent=2))}</pre>"
                )
            name = f" · {turn['name']}" if turn.get("name") else ""
            turns.append(
                (
                    "<div class='turn{attack}'>"
                    "<header><span>{index:02d} / {role}</span>"
                    "<span>{label}</span></header>"
                    "<pre>{content}</pre>{tool_calls}</div>"
                ).format(
                    attack=" attack" if attack else "",
                    index=turn["index"] + 1,
                    role=_esc(turn["role"] + name),
                    label="ATTACK TURN" if attack else "",
                    content=_esc(turn["content"]),
                    tool_calls=tool_calls,
                )
            )
        tools = ", ".join(
            (tool.get("function") or {}).get("name") or str(tool)
            for tool in entry["tools"]
        )
        schema_notes = "".join(
            f"<li><span class='mono'>{_esc(item.get('tool'))}</span> — "
            f"{_esc(item.get('note'))}</li>"
            for item in entry["schema_sources"]
        )
        errors = "".join(f"<li>{_esc(err)}</li>" for err in entry["validation"]["errors"])
        entry_blocks.append(
            "<article class='artifact-block'>"
            "<div class='artifact-strip'><span class='eyebrow'>SCENARIO → ARTIFACT</span>"
            f"<span class='mono id'>{_esc(entry['scenario_id'])}</span>"
            f"<span class='surface-tag surface-{_esc(entry['surface'])}'>{_esc(entry['surface'])}</span></div>"
            "<div class='artifact-meta'>"
            f"<span>Platform coverage: <strong>{_esc(coverage or 'not recorded')}</strong></span>"
            f"<span>Artifact model: <strong>{_esc(entry['artifact_model'] or 'not recorded')}</strong></span>"
            f"<span>Validation: <strong>{_esc('passed' if entry['validation']['ok'] else 'issues recorded')}</strong></span>"
            f"<span>Tools: <strong>{_esc(tools or 'none')}</strong></span></div>"
            f"<p class='fineprint'>{_esc(entry['surface_reason'])}</p>"
            f"<h4>Transcript turns</h4><div class='conversation'>{''.join(turns)}</div>"
            + (
                f"<details class='technical'><summary>Tool schema derivation</summary><ul>{schema_notes}</ul></details>"
                if schema_notes
                else ""
            )
            + (f"<details class='technical'><summary>Validation details</summary><ul>{errors}</ul></details>" if errors else "")
            + f"<p class='links'><a href='../{_esc(entry['entry'])}'>replay entry</a>"
            + (f" · <a href='../{_esc(entry['meta'])}'>replay metadata</a>" if entry.get("meta") else "")
            + "</p></article>"
        )
    return f"""
<div class="results-inner">
  <div class="metrics">
    {_metric((coverage or 'n/a').title(), 'Garak platform coverage', title='As reported by the Artifact Generator for the generated artifact.')}
    {_metric(validation, 'Artifact validation', variant='mint' if counts['validation_ok'] else 'amber', title='Structural gate on tool pairing, declarations, rubric and injection surface.')}
    {_metric(counts['turns'], 'Transcript turns', title='Conversation turns in the first replay entry.')}
  </div>
  <div class="artifact-list">{"".join(entry_blocks)}</div>
  <p class="fineprint">Derived schemas are adapter-asserted test assumptions from the
  artifact’s system-turn tool declarations — not confirmed deployed interfaces. The
  runner does not execute business tools; proposed tool calls are model output.</p>
</div>
"""


def _render_evaluation(data: dict) -> str:
    evaluations = data["evaluations"]["evaluations"]
    if not evaluations:
        return (
            "<div class='results-inner'><p class='empty'>No evaluation was "
            "dispatched in this run. See the run audit for the stage outcome.</p></div>"
        )
    blocks = []
    for evaluation in evaluations:
        outcome = evaluation.get("outcome") or "inconclusive"
        verdict = {
            "attack_succeeded": ("Attack succeeded", "hit"),
            "attack_not_demonstrated": ("Attack not demonstrated", "clear"),
            "inconclusive": ("Inconclusive", "unknown"),
        }.get(outcome, (outcome.replace("_", " ").title(), "unknown"))
        attempts = evaluation.get("attempts") or []
        attempt_html = ""
        for attempt in attempts:
            tool_calls = ""
            if attempt.get("tool_calls"):
                tool_calls = (
                    "<p class='mono-label'>Proposed tool calls</p>"
                    f"<pre class='code'>{_esc(json.dumps(attempt['tool_calls'], indent=2))}</pre>"
                )
            attempt_html += (
                "<div class='turn attack'><header><span>Target response</span>"
                f"<span>{'usable' if attempt.get('usable') else 'excluded'}</span></header>"
                f"<pre>{_esc(attempt.get('response') or '')}</pre>{tool_calls}</div>"
            )
            if attempt.get("judge_reasoning"):
                attempt_html += (
                    "<div class='judge-reason'><p class='eyebrow'>WHY GARAK REACHED THIS RESULT</p>"
                    f"<p>{_esc(attempt['judge_reasoning'])}</p></div>"
                )
        rubric = evaluation.get("rubric") or {}
        criteria = ""
        if rubric:
            criteria = (
                "<details class='technical'><summary>Judge criteria</summary>"
                f"<pre class='code'>{_esc(rubric.get('judge_prompt') or '')}</pre>"
                "<p><strong>Success criteria</strong></p><ul>"
                + "".join(f"<li>{_esc(item)}</li>" for item in rubric.get("attack_success") or [])
                + "</ul><p><strong>Blocked criteria</strong></p><ul>"
                + "".join(f"<li>{_esc(item)}</li>" for item in rubric.get("attack_blocked") or [])
                + "</ul></details>"
            )
        confidence = evaluation.get("judge_confidence")
        cutoff = evaluation.get("confidence_cutoff")
        blocks.append(
            f"<article class='evaluation-block'><div class='evaluation-verdict {verdict[1]}'>"
            "<span class='eyebrow'>MODEL TEST</span>"
            f"<h3>{_esc(verdict[0])}</h3>"
            f"<p>{_esc(evaluation.get('target_model') or 'target model not recorded')} · "
            f"{len(attempts)} response{'s' if len(attempts) != 1 else ''} evaluated</p>"
            f"<p class='fineprint'>{_esc(evaluation.get('reason') or '')}</p></div>"
            "<div class='metrics'>"
            f"{_metric(f'{confidence}/100' if confidence is not None else 'n/a', 'Judge confidence in attack success')}"
            f"{_metric(cutoff if cutoff is not None else 'n/a', 'Success cutoff')}"
            f"{_metric(evaluation.get('judge_model') or 'n/a', 'Judge model', variant='mint')}"
            "</div>"
            f"<div class='artifact-strip'><span class='eyebrow'>ARTIFACT → TARGET → JUDGE</span>"
            f"<span class='mono id'>{_esc(evaluation['scenario_id'])}</span></div>"
            f"<p class='fineprint'>Surface: {_esc(evaluation.get('surface') or 'not recorded')} · "
            f"Detector: {_esc(evaluation.get('detector') or 'not recorded')} · "
            f"Evidence: <span class='mono'>{_esc(evaluation.get('dispatch_dir') or '')}</span></p>"
            f"<div class='conversation'>{attempt_html}</div>{criteria}"
            "<p class='fineprint'>One scenario does not establish overall model safety. "
            "A proposed tool call is captured model output; external tools are not executed "
            "by the runner.</p></article>"
        )
    return f"<div class='results-inner'><div class='evaluation-list'>{''.join(blocks)}</div></div>"


def _render_audit(data: dict, summary: dict, conversation: str | None) -> str:
    audit = data["audit"]
    decisions = audit["decisions"]
    attempts = audit["attempts"]
    reviews = audit["reviews"]
    models = audit["models"]
    scope = audit["scope"]

    timeline: list[tuple[str, str]] = []
    for decision in decisions:
        timeline.append(
            (
                decision.get("recorded_at") or "",
                "<li class='timeline-review'><span class='timeline-time'>{time}</span>"
                "<div><strong>Review · {category}</strong>"
                "<p class='actor'>{actor}</p>{question}{response}</div></li>".format(
                    time=_esc(_fmt_ts(decision.get("recorded_at"))),
                    category=_esc(decision.get("category")),
                    actor=_esc(decision.get("actor")),
                    question=(
                        f"<p>{_esc(decision['question'])}</p>"
                        if decision.get("question")
                        else ""
                    ),
                    response=(
                        f"<p class='response'>{_esc(decision['response'])}</p>"
                        if decision.get("response")
                        else ""
                    ),
                ),
            )
        )
    for attempt in attempts:
        status = _STATUS_LABEL.get(attempt.get("status"), attempt.get("status") or "recorded")
        counts = ", ".join(f"{k}: {v}" for k, v in attempt.get("counts", {}).items() if v is not None)
        detail = " · ".join(
            part
            for part in (
                _duration_text(attempt.get("duration_seconds")),
                counts,
                f"model: {attempt['model']}" if attempt.get("model") else "",
            )
            if part
        )
        problems = ""
        if attempt.get("blockers"):
            problems = "<ul class='problems'>" + "".join(
                f"<li>{_esc(b)}</li>" for b in attempt["blockers"]
            ) + "</ul>"
        elif attempt.get("error"):
            problems = f"<p class='problems'>{_esc(attempt['error'])}</p>"
        timeline.append(
            (
                attempt.get("completed_at") or attempt.get("started_at") or "",
                "<li class='timeline-stage'><span class='timeline-time'>{time}</span>"
                "<div><strong>{stage} · attempt {aid} · {status}</strong>"
                "<p class='detail'>{detail}</p>{problems}</div></li>".format(
                    time=_esc(_fmt_ts(attempt.get("completed_at") or attempt.get("started_at"))),
                    stage=_esc(attempt["stage"]),
                    aid=_esc(attempt["attempt_id"]),
                    status=_esc(status),
                    detail=_esc(detail),
                    problems=problems,
                ),
            )
        )
    timeline.sort(key=lambda item: item[0])
    timeline_html = "".join(item[1] for item in timeline)

    model_rows = "".join(
        "<tr><td>{role}</td><td>{model}</td><td>{host}</td><td>{shared}</td></tr>".format(
            role=_esc(m["role"]),
            model=_esc(m["model"]),
            host=_esc(m["host"] or "not recorded"),
            shared="shared role" if m["shared"] else "",
        )
        for m in models
    )
    review_rows = "".join(
        f"<li><span class='mono'>{_esc(r['kind'])}</span> · {_esc(r['role'])} · "
        f"<a href='../{_esc(r['path'])}'>{_esc(r['name'])}</a></li>"
        for r in reviews
    ) or "<li>No review files recorded</li>"
    attempt_rows = "".join(
        "<details class='attempt'><summary><span>{stage} · {aid}</span>"
        "<span>{status} · {duration}</span></summary>"
        "<p class='fineprint'>{counts}</p>{command}</details>".format(
            stage=_esc(a["stage"]),
            aid=_esc(a["attempt_id"]),
            status=_esc(_STATUS_LABEL.get(a.get("status"), a.get("status") or "recorded")),
            duration=_esc(_duration_text(a.get("duration_seconds")) or "duration not recorded"),
            counts=_esc(", ".join(f"{k}: {v}" for k, v in a.get("counts", {}).items() if v is not None) or "no counts recorded"),
            command=(
                f"<pre class='code'>{_esc(a['command'])}</pre>"
                if a.get("command")
                else ""
            ),
        )
        for a in attempts
    ) or "<p class='empty'>No stage attempts recorded.</p>"
    scope_html = " · ".join(f"{_esc(k)}: {_esc(v)}" for k, v in scope.items() if v is not None)
    conversation_html = ""
    if conversation:
        conversation_html = (
            "<h3 class='audit-subhead'>Conversation with the agent</h3>"
            "<div class='conversation-transcript'>"
            + _render_conversation(conversation)
            + "</div>"
        )
    evidence_links = "".join(
        f"<li><a href='../{_esc(rel)}'>{_esc(label)}</a></li>"
        for rel, label in (
            ("decisions.jsonl", "Decision journal"),
            ("inventory.json", "Evidence inventory"),
            ("originals/run-config.yaml", "Run configuration (original)"),
            ("stages", "Native stage outputs"),
        )
    )
    return f"""
<div class="results-inner">
  <p class="audit-intro">What was run, in what order, and who decided what. Every entry
  below comes from the run's own receipts and decision journal.</p>
  <div class="audit-grid">
    <div class="audit-card"><span class="eyebrow">RUN</span>
      <p>{_esc(summary.get('label') or summary.get('run_id'))}</p>
      <small class="mono">{_esc(summary.get('run_id'))} · started {_esc(_fmt_ts(audit.get('created_at')))}</small></div>
    <div class="audit-card"><span class="eyebrow">SUBJECT</span>
      <p>{_esc('Proposed design' if audit.get('subject') == 'proposed' else 'Built system')}</p>
      <small>{_esc(audit.get('system_name') or 'System identity not declared')}</small></div>
    <div class="audit-card"><span class="eyebrow">SCOPE</span>
      <p>{_esc(scope_html or 'Default scope')}</p></div>
    <div class="audit-card"><span class="eyebrow">CONFIG HASH</span>
      <p class="mono break">{_esc(audit.get('config_sha256') or 'not recorded')}</p></div>
  </div>
  <h3 class="audit-subhead">Timeline</h3>
  <ol class="timeline">{timeline_html or "<li>No decisions or attempts recorded.</li>"}</ol>
  <div class="audit-columns">
    <section><h3 class="audit-subhead">Review gates</h3><ul class="plain">{review_rows}</ul></section>
    <section><h3 class="audit-subhead">Model roles</h3>
      <table class="audit-table"><thead><tr><th>Role</th><th>Requested model</th>
      <th>Endpoint host</th><th></th></tr></thead><tbody>{model_rows}</tbody></table>
      <p class="fineprint">Models are recorded as requested; returned model IDs are unknown
      unless a stage captured them. A shared role is flagged, not judged.</p></section>
  </div>
  <h3 class="audit-subhead">Stage attempts</h3>
  <div class="attempts">{attempt_rows}</div>
  {conversation_html}
  <h3 class="audit-subhead">Evidence</h3>
  <ul class="plain">{evidence_links}</ul>
  <p class="fineprint">This page is a derived convenience view. Native component outputs and
  the decision journal are the retained evidence. It establishes recorded consistency, not
  provider identity, hidden HTTP retries or attestation truth.</p>
</div>
"""


_LINK_RE = re.compile(r"`([^`]+)`")
_BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")


def _render_conversation(text: str) -> str:
    """A deliberately small markdown-ish renderer for an attached transcript.

    Every value is escaped first; the only markup introduced is from this
    function's own fixed templates.
    """
    blocks: list[str] = []
    paragraph: list[str] = []
    bullets: list[str] = []
    code: list[str] = []
    in_code = False

    def flush_paragraph() -> None:
        if paragraph:
            body = _inline(" ".join(paragraph))
            blocks.append(f"<p>{body}</p>")
            paragraph.clear()

    def flush_bullets() -> None:
        if bullets:
            blocks.append("<ul>" + "".join(f"<li>{_inline(b)}</li>" for b in bullets) + "</ul>")
            bullets.clear()

    for raw in text.splitlines():
        line = raw.rstrip()
        if line.strip().startswith("```"):
            if in_code:
                blocks.append(f"<pre class='code'>{_esc(chr(10).join(code))}</pre>")
                code.clear()
                in_code = False
            else:
                flush_paragraph()
                flush_bullets()
                in_code = True
            continue
        if in_code:
            code.append(line)
            continue
        stripped = line.strip()
        if not stripped:
            flush_paragraph()
            flush_bullets()
        elif stripped.startswith("#"):
            flush_paragraph()
            flush_bullets()
            level = min(4, len(stripped) - len(stripped.lstrip("#")))
            blocks.append(f"<h{level + 2}>{_inline(stripped.lstrip('#').strip())}</h{level + 2}>")
        elif stripped.startswith(("- ", "* ")):
            flush_paragraph()
            bullets.append(stripped[2:])
        elif stripped.startswith("> "):
            flush_paragraph()
            flush_bullets()
            blocks.append(f"<blockquote class='policy-quote'><p>{_inline(stripped[2:])}</p></blockquote>")
        else:
            paragraph.append(stripped)
    if in_code:
        blocks.append(f"<pre class='code'>{_esc(chr(10).join(code))}</pre>")
    flush_paragraph()
    flush_bullets()
    return "".join(blocks)


def _inline(text: str) -> str:
    escaped = _esc(text)
    escaped = _LINK_RE.sub(r"<code>\1</code>", escaped)
    escaped = _BOLD_RE.sub(r"<strong>\1</strong>", escaped)
    return escaped


_CSS = """
:root {
  --primary: #2d7ff9;
  --secondary: #0dd4a0;
  --amber: #f5b84d;
  --page: #000108;
  --card: #0b1020;
  --subtle: #05080f;
  --text: #f8fafc;
  --muted: #cbd5e1;
  --border: #151e35;
  --hover: #101b32;
  --link: #7eb0ff;
  --success: #0dd4a0;
  --success-bg: #062b25;
  --selection: #0d2345;
  --danger: #fb8c86;
  --table-header: #1c3150;
  color-scheme: dark;
}
body.light {
  --page: #f4f7fb; --card: #ffffff; --subtle: #edf2fa; --text: #0b1020;
  --muted: #52637b; --border: #dce5f2; --hover: #eaf2ff; --link: #1763ce;
  --success: #08775d; --success-bg: #e1f8f0; --selection: #e9f2ff;
  --table-header: #e2edfc; --danger: #b42318; color-scheme: light;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body { margin: 0; background: var(--page); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Ubuntu,
  Cantarell, "Helvetica Neue", sans-serif; font-size: 15px; line-height: 1.6; }
a { color: var(--link); text-underline-offset: .18em; }
button { font: inherit; cursor: pointer; }
button:focus-visible, a:focus-visible, summary:focus-visible, select:focus-visible,
input:focus-visible { outline: 2px solid var(--secondary); outline-offset: 3px; }
h1, h2, h3, h4 { letter-spacing: -.03em; line-height: 1.2; margin: 0; }
h1 { font-size: clamp(30px, 3.1vw, 46px); font-weight: 650; }
h2 { font-size: 27px; font-weight: 620; margin-bottom: 6px; }
h3 { font-size: 19px; font-weight: 600; }
h4 { font-size: 14px; font-weight: 650; margin: 22px 0 8px; }
p { margin: 0 0 12px; }
pre, code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas,
  "Liberation Mono", monospace; }
.asago-header { --text: #f8fafc; --muted: #cbd5e1; --link: #7eb0ff;
  display: flex; align-items: center; justify-content: space-between;
  gap: 20px; padding: 0 4vw; height: 84px; background: linear-gradient(135deg, #05080f, #060c1a);
  border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 20;
  background-color: var(--subtle); }
.asago-header::before { content: ""; position: absolute; inset: 0 0 auto; height: 3px;
  background: linear-gradient(90deg, var(--primary), var(--secondary)); }
.brand { display: flex; align-items: center; gap: 22px; }
.asago-logo { display: inline-flex; align-items: center; justify-content: center;
  padding: 6px 16px; border: 2px solid #e2e8f0; border-radius: 8px;
  font-family: ui-monospace, monospace; font-size: 25px; letter-spacing: .08em;
  color: #f8fafc; background: #060b16; }
.asago-product { font-size: 16px; color: var(--text); }
nav.top { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.quiet { padding: 9px 12px; background: transparent; color: var(--muted);
  border: 1px solid transparent; border-radius: 5px; text-decoration: none; }
.quiet:hover { background: var(--hover); color: var(--text); }
main { max-width: 1600px; margin: 0 auto; padding: 40px 4vw 24px; }
.intro { display: flex; align-items: flex-end; justify-content: space-between;
  gap: 32px; margin-bottom: 30px; flex-wrap: wrap; }
.eyebrow { font-size: 11px; letter-spacing: .13em; font-weight: 750;
  color: var(--secondary); margin: 0 0 8px; text-transform: uppercase; }
.intro .lede { color: var(--muted); font-size: 16px; max-width: 54rem; }
.badges { display: flex; gap: 8px; flex-wrap: wrap; }
.badge-pill { border: 1px solid var(--border); background: var(--card);
  color: var(--muted); border-radius: 999px; padding: 5px 12px; font-size: 11px;
  letter-spacing: .05em; text-transform: uppercase; }
.badge-pill.accent { border-color: var(--secondary); color: var(--secondary); }
.context-strip { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 0; border: 1px solid var(--border); background: var(--card); margin-bottom: 20px; }
.context-strip > span { padding: 18px 22px; border-right: 1px solid var(--border);
  min-width: 0; }
.context-strip > span:last-child { border-right: 0; }
.context-strip small { display: block; font-size: 10px; letter-spacing: .12em;
  color: var(--muted); text-transform: uppercase; margin-bottom: 6px; }
.context-strip strong { display: block; font-size: 15px; overflow-wrap: anywhere; }
.pipeline { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 10px; margin: 0 0 22px; }
.stage { display: flex; align-items: center; text-align: left; gap: 12px;
  background: var(--card); border: 1px solid var(--border); padding: 18px 16px;
  color: var(--text); position: relative; min-height: 102px; border-radius: 0; }
.stage:hover:not(:disabled) { border-color: var(--primary); }
.stage.active { border-color: var(--primary); background: var(--selection); }
.stage:disabled { opacity: .45; cursor: not-allowed; }
.step { font-size: 20px; color: var(--secondary); font-variant-numeric: tabular-nums; }
.stage-copy { display: flex; flex-direction: column; gap: 4px; }
.stage-copy strong { font-size: 15px; }
.stage-copy small { font-size: 10px; color: var(--muted); line-height: 1.35; }
.stage-state { position: absolute; top: 8px; right: 12px; text-transform: uppercase;
  letter-spacing: .06em; font-size: 8px; color: var(--muted); }
.stage[data-status="completed"] .stage-state,
.stage[data-status="completed_with_gaps"] .stage-state { color: var(--success); }
.stage[data-status="failed"] .stage-state, .stage[data-status="blocked"] .stage-state,
.stage[data-status="needs_review"] .stage-state { color: var(--amber); }
.stage[data-status="failed"] .stage-state { color: var(--danger); }
.result-shell { border: 1px solid var(--border); background: var(--card);
  border-radius: 7px; overflow: hidden; margin-bottom: 22px; }
.result-heading { padding: 26px 28px; display: flex; justify-content: space-between;
  align-items: flex-start; gap: 24px; border-bottom: 1px solid var(--border); }
.panel-description { color: var(--muted); margin: 0 0 8px; }
.owner-tag { font-size: 12px; color: var(--muted); margin: 0; }
.owner-tag strong { color: var(--secondary); letter-spacing: .04em; }
.result-actions { display: flex; align-items: center; gap: 10px; text-align: right; }
.status-pill { border: 1px solid var(--border); border-radius: 999px;
  padding: 5px 12px; font-size: 11px; color: var(--muted); white-space: nowrap; }
.status-completed { color: var(--success); border-color: var(--success); }
.status-completed_with_gaps, .status-needs_review { color: var(--amber); border-color: var(--amber); }
.status-failed, .status-blocked { color: var(--danger); border-color: var(--danger); }
.results-inner { padding: 26px 28px 30px; }
.metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px; margin-bottom: 12px; }
.metrics.three { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.metric { padding: 18px 20px; border: 1px solid var(--border);
  border-top: 3px solid var(--primary); background: var(--subtle); }
.metric strong { display: block; font-size: clamp(24px, 2.2vw, 34px);
  letter-spacing: -.03em; line-height: 1.25; overflow-wrap: anywhere; }
.metric span { font-size: 12px; color: var(--muted); }
.metric.mint { border-top-color: var(--secondary); }
.metric.amber { border-top-color: var(--amber); }
.metric-note { color: var(--muted); font-size: 12px; margin: 0 0 20px; }
.charts { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px;
  margin: 0 0 26px; }
.chart { padding: 18px 20px; border: 1px solid var(--border);
  background: var(--subtle); min-width: 0; }
.chart h3 { font-size: 12px; font-weight: 650; margin: 0 0 14px; color: var(--muted);
  letter-spacing: .03em; }
.bar-button { display: grid; grid-template-columns: minmax(90px, 1.2fr) 1fr 30px;
  align-items: center; gap: 12px; width: 100%; font-size: 12px; color: var(--text);
  padding: 6px 0; background: none; border: 0; text-align: left; }
.bar-label { overflow-wrap: anywhere; }
.bar-track { display: block; height: 7px; background: var(--hover); border-radius: 2px; }
.bar-track b { display: block; height: 7px; border-radius: 2px;
  background: linear-gradient(90deg, var(--primary), var(--secondary)); min-width: 3px; }
.bar-button strong { text-align: right; font-size: 12px; }
.bar-button:hover .bar-label, .bar-button[aria-pressed="true"] .bar-label { color: var(--secondary); }
.grounding-bar { display: flex; height: 34px; border-radius: 3px; overflow: hidden;
  background: var(--hover); }
.grounding-segment { display: flex; align-items: center; justify-content: center;
  color: #04121d; font-size: 12px; font-weight: 650; }
.grounding-legend { display: grid; grid-template-columns: 1fr 1fr; gap: 10px;
  margin-top: 16px; }
.grounding-legend span { border: 1px solid var(--border); padding: 10px 12px;
  font-size: 12px; display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.grounding-legend i { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
.grounding-legend small { color: var(--muted); margin-left: auto; }
.findings-heading { display: flex; justify-content: space-between; align-items: flex-end;
  gap: 16px; margin: 28px 0 14px; flex-wrap: wrap; }
.findings-heading h3 { font-size: 18px; }
.filter-row { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap;
  margin-bottom: 18px; }
.filter-row label { display: flex; flex-direction: column; gap: 5px; font-size: 11px;
  color: var(--muted); text-transform: uppercase; letter-spacing: .07em; }
.filter-row select, .filter-row input, .scenario-options select {
  padding: 9px 11px; border: 1px solid var(--border); border-radius: 4px;
  background: var(--card); color: var(--text); font-size: 13px; text-transform: none;
  letter-spacing: normal; }
.search-label { flex: 1; min-width: 190px; }
.search-label input { width: 100%; }
.findings { border-top: 1px solid var(--border); }
.finding { border-bottom: 1px solid var(--border); }
.finding[hidden] { display: none; }
.finding > details > summary { display: flex; justify-content: space-between;
  gap: 18px; padding: 15px 4px; cursor: pointer; align-items: flex-start;
  list-style: none; }
.finding > details > summary::-webkit-details-marker { display: none; }
.finding > details[open] > summary { background: var(--subtle); }
.finding-main { display: flex; flex-direction: column; gap: 7px; min-width: 0; }
.finding-name { font-weight: 600; font-size: 15px; }
.finding-meta { display: flex; gap: 10px; align-items: center; flex-wrap: wrap;
  justify-content: flex-end; font-size: 11px; color: var(--muted); }
.finding-id { font-family: ui-monospace, monospace; font-size: 11px; color: var(--muted);
  overflow-wrap: anywhere; }
.finding-body { padding: 4px 6px 22px; max-width: 70rem; }
.chips { display: flex; gap: 6px; flex-wrap: wrap; }
.chip { border-radius: 999px; padding: 2px 9px; font-size: 10px;
  border: 1px solid var(--border); color: var(--muted); }
.theme-privacy { color: #9cc0ff; border-color: #31558f; }
.theme-fairness { color: #e0b3ff; border-color: #6d418f; }
.theme-security { color: #7ef0cc; border-color: #1d6b59; }
.theme-reliability { color: #a9c8ff; border-color: #34577f; }
.theme-human-agency { color: #ffd48d; border-color: #87652a; }
.theme-harmful-content { color: #ffa99b; border-color: #8b3b30; }
.theme-intellectual-property { color: #93e2ec; border-color: #2e6c74; }
.theme-environment { color: #b7e29d; border-color: #47703a; }
.theme-other { color: var(--muted); }
.taxonomy-badge { border: 1px solid var(--border); border-radius: 4px;
  padding: 2px 7px; font-size: 10px; color: var(--muted); }
.badge { border-radius: 4px; padding: 2px 7px; font-size: 10px;
  border: 1px solid var(--border); }
.grounding-high { color: var(--success); border-color: var(--success); }
.grounding-medium { color: var(--amber); border-color: var(--amber); }
.grounding-low { color: #ed865e; border-color: #ed865e; }
.grounding-ungrounded, .grounding-unknown { color: var(--muted); }
.evidence-count { color: var(--muted); }
.policy-quote { margin: 10px 0; padding: 12px 16px; border-left: 3px solid var(--primary);
  background: var(--subtle); }
.policy-quote p { margin: 0 0 6px; }
.policy-quote cite { font-style: normal; font-size: 11px; color: var(--muted); }
.fineprint { font-size: 11.5px; color: var(--muted); line-height: 1.6; }
.empty { color: var(--muted); padding: 8px 0; }
.links a { font-size: 12px; }
.scenario-options { display: flex; gap: 12px; margin: 0 0 16px; }
.scenario-options label { display: flex; flex-direction: column; gap: 5px;
  font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .07em; }
.scenario-list { display: grid; gap: 12px; }
.scenario-card { border: 1px solid var(--border); background: var(--subtle); }
.scenario-card[hidden] { display: none; }
.scenario-top { display: flex; align-items: flex-start; justify-content: space-between;
  gap: 16px; padding: 17px 18px; }
.scenario-copy { min-width: 0; }
.scenario-top h3 { font-size: 16px; margin: 5px 0 0; line-height: 1.5; }
.scenario-top .id { font-size: 11px; color: var(--muted); overflow-wrap: anywhere; }
.surface-tag { border: 1px solid var(--border); border-radius: 4px; padding: 3px 9px;
  font-size: 10px; letter-spacing: .06em; color: var(--muted); white-space: nowrap; }
.surface-user_turn { color: var(--link); border-color: #31558f; }
.surface-tool_return { color: var(--secondary); border-color: #1d6b59; }
.scenario-card details { border-top: 1px solid var(--border); }
.scenario-card summary { padding: 12px 18px; cursor: pointer; font-size: 12px;
  color: var(--muted); }
.scenario-body { padding: 6px 22px 22px; max-width: 74rem; }
.trace { border-left: 3px solid var(--primary); padding: 4px 0 4px 16px; margin: 16px 0; }
.steps { padding-left: 20px; margin: 0 0 16px; }
.steps li { margin-bottom: 8px; }
.zone { font-family: ui-monospace, monospace; font-size: 10px; color: var(--secondary);
  border: 1px solid var(--border); padding: 1px 6px; margin-right: 6px; }
.code { white-space: pre-wrap; overflow-wrap: anywhere; background: var(--subtle);
  border: 1px solid var(--border); padding: 14px 16px; font-size: 12px;
  line-height: 1.6; margin: 8px 0 16px; max-height: 26rem; overflow: auto; }
.artifact-list, .evaluation-list { display: grid; gap: 18px; }
.artifact-block, .evaluation-block { border: 1px solid var(--border); background: var(--subtle);
  padding: 20px 22px; }
.artifact-strip { display: flex; align-items: center; gap: 14px; flex-wrap: wrap;
  padding: 10px 0; border-bottom: 1px solid var(--border); margin-bottom: 14px; }
.artifact-strip .eyebrow { margin: 0; }
.artifact-strip .id { font-size: 11px; color: var(--muted); overflow-wrap: anywhere; }
.artifact-meta { display: flex; gap: 18px; flex-wrap: wrap; font-size: 12px;
  color: var(--muted); margin-bottom: 10px; }
.artifact-meta strong { color: var(--text); }
.conversation { display: grid; gap: 12px; }
.turn { border: 1px solid var(--border); padding: 16px 18px; background: var(--card); }
.turn.attack { border-color: var(--primary); background: var(--selection); }
.turn header { display: flex; justify-content: space-between; gap: 10px;
  align-items: center; margin-bottom: 10px; font-size: 11px; color: var(--muted);
  text-transform: uppercase; letter-spacing: .05em; }
.turn pre { margin: 0; white-space: pre-wrap; font-family: inherit; font-size: 13px;
  line-height: 1.7; overflow-wrap: anywhere; }
.mono-label { font-size: 11px; color: var(--muted); text-transform: uppercase;
  letter-spacing: .06em; margin: 14px 0 4px; }
.evaluation-verdict { padding: 24px 26px; border: 1px solid var(--secondary);
  background: var(--card); margin-bottom: 16px; }
.evaluation-verdict.hit { border-color: #ed865e; }
.evaluation-verdict.unknown { border-color: var(--amber); }
.evaluation-verdict h3 { font-size: clamp(26px, 3vw, 38px); margin: 10px 0 6px; }
.evaluation-verdict p { color: var(--muted); }
.judge-reason { padding: 16px 18px; border: 1px solid var(--border); background: var(--card); }
.judge-reason p { color: var(--muted); }
.technical { border: 1px solid var(--border); background: var(--card); margin: 14px 0; }
.technical > summary { padding: 12px 16px; cursor: pointer; font-size: 12px; color: var(--muted); }
.technical > *:not(summary) { margin: 0 16px 14px; }
.traceability { display: grid; gap: 10px; }
.traceability div { display: flex; align-items: baseline; gap: 10px; }
.traceability strong { font-size: 24px; color: var(--secondary); min-width: 40px; }
.traceability span { font-size: 12px; color: var(--muted); }
.audit-intro { color: var(--muted); max-width: 60rem; }
.audit-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px; margin: 18px 0 26px; }
.audit-card { border: 1px solid var(--border); background: var(--subtle); padding: 16px 18px; }
.audit-card p { margin: 8px 0 6px; font-size: 14px; overflow-wrap: anywhere; }
.audit-card small { color: var(--muted); font-size: 11px; }
.audit-subhead { font-size: 14px; text-transform: uppercase; letter-spacing: .09em;
  color: var(--muted); margin: 28px 0 14px; }
.break { overflow-wrap: anywhere; }
.timeline { list-style: none; padding: 0; margin: 0; border-left: 1px solid var(--border); }
.timeline li { display: grid; grid-template-columns: 190px 1fr; gap: 20px;
  padding: 12px 0 12px 20px; position: relative; }
.timeline li::before { content: ""; position: absolute; left: -5px; top: 20px;
  width: 9px; height: 9px; border-radius: 50%; background: var(--primary); }
.timeline .timeline-review::before { background: var(--secondary); }
.timeline-time { font-size: 11px; color: var(--muted); font-variant-numeric: tabular-nums; }
.timeline strong { font-size: 14px; }
.timeline p { font-size: 13px; color: var(--muted); margin: 4px 0 0; }
.timeline .actor { font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }
.timeline .detail { font-size: 12px; color: var(--muted); margin: 4px 0 0; }
.timeline .response { color: var(--text); }
.problems { color: var(--amber); font-size: 12px; margin: 6px 0 0; padding-left: 18px; }
.audit-columns { display: grid; grid-template-columns: 1fr 1fr; gap: 28px; }
.audit-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.audit-table th, .audit-table td { border: 1px solid var(--border); padding: 8px 10px;
  text-align: left; vertical-align: top; }
.audit-table th { background: var(--table-header); color: var(--text); font-weight: 600; }
.plain { list-style: none; padding: 0; margin: 0; }
.plain li { padding: 7px 0; border-bottom: 1px solid var(--border); font-size: 13px; }
.attempts { display: grid; gap: 8px; }
.attempt { border: 1px solid var(--border); background: var(--subtle); }
.attempt > summary { display: flex; justify-content: space-between; gap: 12px;
  padding: 11px 14px; cursor: pointer; font-size: 12px; }
.attempt .code { margin: 0 14px 14px; }
.conversation-transcript { border: 1px solid var(--border); background: var(--subtle);
  padding: 18px 22px; max-width: 76rem; }
.conversation-transcript h3 { font-size: 17px; margin: 20px 0 8px; }
.conversation-transcript h4 { font-size: 15px; margin: 18px 0 8px; }
.conversation-transcript ul { padding-left: 20px; }
footer { border-top: 1px solid var(--border); margin-top: 30px; padding: 22px 4vw 40px;
  color: var(--muted); font-size: 11.5px; display: flex; gap: 20px;
  justify-content: space-between; flex-wrap: wrap; }
[hidden] { display: none !important; }
@media (max-width: 1150px) {
  .pipeline { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .charts { grid-template-columns: 1fr 1fr; }
  .audit-grid { grid-template-columns: 1fr 1fr; }
  .metrics { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 760px) {
  .asago-header { height: auto; padding: 14px 16px; flex-wrap: wrap; }
  main { padding: 24px 16px; }
  .pipeline, .context-strip, .charts, .metrics, .audit-grid, .audit-columns {
    grid-template-columns: 1fr; }
  .context-strip > span { border-right: 0; border-bottom: 1px solid var(--border); }
  .result-heading { flex-direction: column; }
  .results-inner { padding: 18px 16px; }
  .finding > details > summary { flex-direction: column; }
  .finding-meta { justify-content: flex-start; }
  .timeline li { grid-template-columns: 1fr; gap: 2px; }
}
@media print {
  body { background: #fff; color: #111; }
  .asago-header, .pipeline, .result-actions, #theme-toggle { display: none !important; }
  .result-shell, .artifact-block, .scenario-card, .evaluation-block { break-inside: avoid; }
  .panel[hidden] { display: block !important; }
  .result-shell, .artifact-block, .scenario-card, .evaluation-block, .chart,
  .metric, .audit-card, .turn, .technical, .conversation-transcript, .code,
  .policy-quote { background: #fff !important; color: #111 !important;
  border-color: #aaa !important; }
  .fineprint, .metric span, .panel-description, .owner-tag, .timeline-time,
  .timeline p, .artifact-meta, .finding-meta { color: #444 !important; }
  a { color: #111; }
}
"""

_JS = """
(function () {
  "use strict";
  var buttons = Array.prototype.slice.call(
    document.querySelectorAll(".stage[data-panel]")
  );
  function activate(key) {
    buttons.forEach(function (button) {
      var on = button.getAttribute("data-panel") === key;
      button.classList.toggle("active", on);
      button.setAttribute("aria-selected", on ? "true" : "false");
    });
    Array.prototype.forEach.call(document.querySelectorAll(".panel"), function (panel) {
      panel.hidden = panel.id !== "panel-" + key;
    });
  }
  buttons.forEach(function (button) {
    button.addEventListener("click", function () {
      activate(button.getAttribute("data-panel"));
      document.getElementById("panels").scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });
  var initial = document.querySelector(".stage[data-panel]:not(:disabled)");
  Array.prototype.forEach.call(
    document.querySelectorAll("[data-panel-link]"),
    function (link) {
      link.addEventListener("click", function (event) {
        event.preventDefault();
        activate(link.getAttribute("data-panel-link"));
        document.getElementById("panels").scrollIntoView({ behavior: "smooth" });
      });
    }
  );
  var wanted = (location.hash || "").replace("#panel-", "").replace("#", "");
  if (wanted && document.getElementById("panel-" + wanted)) {
    activate(wanted);
  } else if (initial) {
    activate(initial.getAttribute("data-panel"));
  }

  var findings = Array.prototype.slice.call(document.querySelectorAll(".finding"));
  var selects = {
    theme: document.querySelector('[data-filter="theme"]'),
    taxonomy: document.querySelector('[data-filter="taxonomy"]'),
    grounding: document.querySelector('[data-filter="grounding"]')
  };
  var search = document.getElementById("risk-search");
  var count = document.getElementById("finding-count");
  var reset = document.getElementById("reset-filters");
  function matches(finding) {
    var theme = selects.theme ? selects.theme.value : "";
    var taxonomy = selects.taxonomy ? selects.taxonomy.value : "";
    var grounding = selects.grounding ? selects.grounding.value : "";
    var term = search ? search.value.trim().toLowerCase() : "";
    if (theme) {
      var themes = (finding.getAttribute("data-theme") || "").split(" ");
      if (themes.indexOf(theme) === -1) return false;
    }
    if (taxonomy && finding.getAttribute("data-taxonomy") !== taxonomy) return false;
    var level = finding.getAttribute("data-grounding") || "";
    if (grounding === "review" && !["medium", "low", "ungrounded"].includes(level)) return false;
    if (grounding && grounding !== "review" && level !== grounding) return false;
    if (term && (finding.getAttribute("data-search") || "").toLowerCase().indexOf(term) === -1) return false;
    return true;
  }
  function apply() {
    var shown = 0;
    findings.forEach(function (finding) {
      var visible = matches(finding);
      finding.hidden = !visible;
      if (visible) shown += 1;
    });
    if (count) count.textContent = shown + " of " + findings.length + " matches";
  }
  Object.keys(selects).forEach(function (key) {
    if (selects[key]) selects[key].addEventListener("change", apply);
  });
  if (search) search.addEventListener("input", apply);
  if (reset) {
    reset.addEventListener("click", function () {
      Object.keys(selects).forEach(function (key) {
        if (selects[key]) selects[key].value = "";
      });
      if (search) search.value = "";
      Array.prototype.forEach.call(document.querySelectorAll(".bar-button"), function (b) {
        b.setAttribute("aria-pressed", "false");
      });
      apply();
    });
  }
  Array.prototype.forEach.call(document.querySelectorAll(".bar-button"), function (button) {
    button.addEventListener("click", function () {
      var kind = button.getAttribute("data-filter-kind");
      var value = button.getAttribute("data-filter-value");
      var select = selects[kind] || document.getElementById("surface-filter");
      if (select) {
        select.value = value;
        if (kind === "surface") {
          Array.prototype.forEach.call(document.querySelectorAll(".scenario-card"), function (card) {
            card.hidden = !!value && card.getAttribute("data-surface") !== value;
          });
        } else {
          apply();
        }
        var target = kind === "surface"
          ? document.querySelector(".scenario-list")
          : document.getElementById("findings");
        if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
      }
      Array.prototype.forEach.call(document.querySelectorAll(".bar-button"), function (b) {
        b.setAttribute("aria-pressed", b === button ? "true" : "false");
      });
    });
  });
  var surface = document.getElementById("surface-filter");
  if (surface) {
    surface.addEventListener("change", function () {
      Array.prototype.forEach.call(document.querySelectorAll(".scenario-card"), function (card) {
        card.hidden = !!surface.value && card.getAttribute("data-surface") !== surface.value;
      });
    });
  }

  var toggle = document.getElementById("theme-toggle");
  function setLight(light) {
    document.body.classList.toggle("light", light);
    if (toggle) toggle.textContent = light ? "Dark mode" : "Light mode";
    try { localStorage.setItem("asago-report-light", light ? "1" : "0"); } catch (e) {}
  }
  var saved = null;
  try { saved = localStorage.getItem("asago-report-light"); } catch (e) {}
  setLight(saved === "1");
  if (toggle) toggle.addEventListener("click", function () {
    setLight(!document.body.classList.contains("light"));
  });
})();
"""


def _context_models(audit: dict) -> str:
    models = [m["model"] for m in audit.get("models", []) if m.get("model")]
    unique = list(OrderedDict.fromkeys(models))
    if not unique:
        return "not recorded"
    if len(unique) <= 2:
        return " · ".join(unique)
    return " · ".join(unique[:2]) + f" +{len(unique) - 2} roles"


def render_page(
    run: RunDir,
    summary: dict,
    data: dict,
    *,
    conversation: str | None = None,
) -> Path:
    """Render the self-contained offline HTML report."""
    states = stage_states(summary, data)
    state_by_key = {state["key"]: state for state in states}
    audit = data.get("audit") or {}

    panels: list[str] = []
    content_by_key = {
        "policy": lambda: _render_policy(data),
        "scenarios": lambda: _render_scenarios(data),
        "artifact": lambda: _render_artifact(data),
        "evaluation": lambda: _render_evaluation(data),
        "audit": lambda: _render_audit(data, summary, conversation),
    }
    for spec in STAGE_SPECS:
        state = state_by_key[spec["key"]]
        if spec["key"] != "audit" and state["status"] == "not-run":
            continue
        spec_for_head = dict(spec)
        panels.append(
            f"<section class='result-shell panel' id='panel-{spec['key']}'>"
            + _panel_head(spec_for_head, state)
            + content_by_key[spec["key"]]()
            + "</section>"
        )

    stage_html = "".join(
        "<button type='button' class='stage{active}' data-panel='{key}' "
        "data-status='{status}'{disabled} title='{reason}'>"
        "<span class='step'>{step}</span>"
        "<span class='stage-copy'><strong>{title}</strong><small>{subtitle}</small></span>"
        "<span class='stage-state'>{label}</span></button>".format(
            active=" active" if state["key"] == "policy" else "",
            key=_esc(state["key"]),
            status=_esc(state["status"]),
            disabled=" disabled" if state["status"] == "not-run" else "",
            reason=_esc(state.get("reason") or ""),
            step=_esc(state["step"]),
            title=_esc(state["title"]),
            subtitle=_esc(state["subtitle"]),
            label=_esc(state["label"]),
        )
        for state in states
    )
    disabled_notes = ""
    if summary.get("subject") != "proposed":
        disabled_notes = "".join(
            f"<p class='fineprint'><strong>{_esc(state['title'])}</strong> — "
            f"{_esc(state['label'])}. {_esc(state.get('reason') or '')}</p>"
            for state in states
            if state["status"] == "not-run"
        )

    policy_docs = audit.get("policy_documents") or []
    if len(policy_docs) == 1:
        policy_label = Path(str(policy_docs[0].get("path") or "")).name
    elif policy_docs:
        policy_label = f"{len(policy_docs)} policy documents"
    else:
        policy_label = "not recorded"
    subject = "Proposed design" if summary.get("subject") == "proposed" else "Built system"
    models_label = _context_models(audit)
    run_label = summary.get("label") or summary.get("run_id")

    subject_note = ""
    if summary.get("subject") == "proposed":
        subject_note = (
            "<p class='fineprint'><strong>Design-time run.</strong> The subject is a "
            "proposed design, not a built system: the run stops after the Scenario "
            "Generator. The scenarios are the threat picture for the design as "
            "described; no artifact was generated and no evaluation is possible "
            "until the system is built.</p>"
        )

    generated = _fmt_ts(summary.get("generated_at"))
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Asago run report — {_esc(run_label)}</title>
<style>{_CSS}</style>
</head>
<body class="asago-report">
<header class="asago-header">
  <div class="brand"><span class="asago-logo">asago</span>
    <span class="asago-product">Run report</span></div>
  <nav class="top" aria-label="Report utilities">
    <button type="button" id="theme-toggle" class="quiet">Light mode</button>
    <a class="quiet" href="#panel-audit" data-panel-link="audit">Run audit</a>
  </nav>
</header>
<main>
  <section class="intro">
    <div>
      <p class="eyebrow">POLICY-DRIVEN AGENTIC RED TEAMING</p>
      <h1>From policy to model evaluation.</h1>
      <p class="lede">Policy documents → grounded risk evidence → adversarial
      scenarios → Garak artifacts → real target responses and a verdict.</p>
    </div>
    <div class="badges">
      <span class="badge-pill accent">{_esc(subject)}</span>
      <span class="badge-pill">Run {_esc(summary.get('run_id'))}</span>
      <span class="badge-pill">Generated {_esc(generated)}</span>
    </div>
  </section>
  <section class="context-strip" aria-label="Run context">
    <span><small>POLICY</small><strong>{_esc(policy_label)}</strong></span>
    <span><small>SYSTEM</small><strong>{_esc(audit.get('system_name') or 'Identity not declared')}</strong></span>
    <span><small>CONFIGURED MODELS</small><strong title="{_esc(', '.join(m['role'] + ': ' + m['model'] for m in audit.get('models', [])))}">{_esc(models_label)}</strong></span>
    <span><small>RUN</small><strong>{_esc(run_label)}</strong></span>
  </section>
  <nav class="pipeline" aria-label="Pipeline stages">{stage_html}</nav>
  {disabled_notes}
  {subject_note}
  <div id="panels">{''.join(panels)}</div>
</main>
<footer>
  <span>Asago · Policy → scenario → artifact → evaluation</span>
  <span>Offline static report. No scripts load from the network; no credentials
  or model calls are needed to read it.</span>
</footer>
<script>{_JS}</script>
</body>
</html>
"""
    out = run.path / "reports" / "index.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(document, encoding="utf-8")
    return out

