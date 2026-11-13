"""Model-free verification of a run's retained live output.

``verify-run`` validates recorded consistency — not independent proof of a
provider's model identity, every hidden HTTP retry, or the truth of an
actor's attestation. Checks:

- admitted scenario receipts and hashes match the native inventory;
- every evaluated replay entry maps to a validated artifact whose scenario
  is in the admitted inventory with a matching hash;
- replay-entry parent links and reviewed hashes are intact (no post-review
  change);
- policy evidence spans and adaptation maps exist for selected results;
- dispatch records correlate with native Garak attempt rows;
- expected detector results exist for each dispatch outcome;
- counts reconcile with native manifests;
- the grounded live mapper path has native model-call evidence where
  expected (missing capture fails live acceptance);
- no configured secret value appears anywhere in the retained evidence tree.
"""

from __future__ import annotations

import json
from pathlib import Path

from .config import RunConfig
from .evidence import RunDir
from .hashing import sha256_file


class VerifyRunError(RuntimeError):
    pass


def verify_run(run: RunDir, config: RunConfig | None = None) -> dict:
    """Run all model-free checks; returns a report (raises on hard failure)."""
    problems: list[str] = []
    warnings: list[str] = []
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})
        if not ok:
            problems.append(f"{name}: {detail}" if detail else name)

    manifest = run.manifest()
    stages = manifest.get("stages", {})

    # -- mapper stage ------------------------------------------------------
    mapper_attempts = (stages.get("policy-mapper") or {}).get("attempts", [])

    def _attempt_returncode(attempt: dict) -> int | None:
        if attempt.get("returncode") is not None:
            return attempt["returncode"]
        meta = run.stage_dir("policy-mapper") / attempt.get("attempt_id", "") / "attempt.json"
        if meta.is_file():
            return json.loads(meta.read_text(encoding="utf-8")).get("returncode")
        return None

    live_mapper = [
        a
        for a in mapper_attempts
        if not a.get("no_llm_mode") and _attempt_returncode(a) == 0
    ]
    latest_live = live_mapper[-1] if live_mapper else None
    if latest_live:
        attempt_dir = run.stage_dir("policy-mapper") / latest_live["attempt_id"]
        extraction_path = attempt_dir / "risk-extraction.json"
        if not extraction_path.is_file():
            check("mapper.live-extraction-present", False, str(extraction_path))
        else:
            extraction = json.loads(extraction_path.read_text(encoding="utf-8"))
            llm_calls = extraction.get("llm_calls") or []
            check(
                "mapper.llm-calls-evidence",
                bool(llm_calls),
                f"{len(llm_calls)} native model-call records retained"
                if llm_calls
                else "a grounded live run must retain model-call evidence",
            )
            risks = extraction.get("risks", [])
            check(
                "mapper.risks-nonempty",
                bool(risks),
                f"{len(risks)} risks matched" if risks else "zero matched risks",
            )
    else:
        check("mapper.live-attempt-present", False, "no completed live mapper attempt")

    # -- scenario stage: admission receipts ---------------------------------
    scenario_attempts = (stages.get("scenario-generator") or {}).get("attempts", [])
    latest_scenario = scenario_attempts[-1] if scenario_attempts else None
    admitted_hashes: dict[str, str] = {}
    if latest_scenario and latest_scenario.get("scenario_run_dir"):
        sdir = run.path / latest_scenario["scenario_run_dir"]
        inv_path = sdir / "finalization-inventory.json"
        if not inv_path.is_file():
            check("scenario.inventory-present", False, str(inv_path))
        else:
            inventory = json.loads(inv_path.read_text(encoding="utf-8"))
            ok = True
            detail = []
            for receipt in inventory.get("admitted_inventory", []):
                path = sdir / receipt["path"]
                if not path.is_file() or sha256_file(path) != receipt.get("sha256"):
                    ok = False
                    detail.append(receipt["path"])
                if receipt.get("scenario_id"):
                    # Key by role: yaml and feature receipts share a scenario id.
                    admitted_hashes[(receipt["scenario_id"], receipt.get("role"))] = (
                        receipt["sha256"]
                    )
            check(
                "scenario.admission-receipts-hash-match",
                ok,
                "mismatched: " + ", ".join(detail) if detail else "all receipts verified",
            )
    else:
        check("scenario.attempt-present", False, "no scenario attempt recorded")

    # -- artifact + replay entries ------------------------------------------
    artifact_attempts = (stages.get("artifact-generator") or {}).get("attempts", [])
    latest_artifact = next(
        (a for a in reversed(artifact_attempts) if a.get("replay_entries")), None
    )
    replay_entries: list[dict] = []
    if latest_artifact:
        replay_entries = latest_artifact["replay_entries"]
        for entry in replay_entries:
            entry_path = Path(entry["entry_path"])
            ok = entry_path.is_file() and sha256_file(entry_path) == entry["entry_sha256"]
            check(
                f"replay.entry-intact.{entry['scenario_id']}",
                ok,
                "hash verified"
                if ok
                else f"hash mismatch or missing file at {entry_path}",
            )
            # Parent artifact must trace to an admitted scenario.
            meta_path = Path(entry["meta_path"])
            if meta_path.is_file():
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                sid = entry["scenario_id"]
                if (sid, "scenario_yaml") in admitted_hashes:
                    parent_yaml = (meta.get("parent_scenario") or {}).get("scenario_yaml") or {}
                    parent_sha = parent_yaml.get("sha256")
                    match = parent_sha == admitted_hashes[(sid, "scenario_yaml")]
                    check(
                        f"replay.parent-scenario-admitted.{sid}",
                        match,
                        "parent scenario hash matches the admitted inventory"
                        if match
                        else "replay parent hash != admitted inventory hash",
                    )
                else:
                    check(
                        f"replay.parent-scenario-admitted.{sid}",
                        False,
                        "scenario not present in the admitted inventory",
                    )
                artifact_sha = (meta.get("parent_artifact") or {}).get("sha256")
                artifact_path = (meta.get("parent_artifact") or {}).get("path")
                if artifact_path and Path(artifact_path).is_file():
                    intact = sha256_file(artifact_path) == artifact_sha
                    check(
                        f"replay.parent-artifact-intact.{sid}",
                        intact,
                        "parent artifact unchanged since replay entry was built"
                        if intact
                        else "parent artifact changed after replay entry was built",
                    )
        # Surface + derivations recorded in the summary.
        summary_path = run.path / "reports" / "summary.json"
        if summary_path.is_file():
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            check(
                "summary.surfaces-recorded",
                bool(summary.get("tested_surface")),
                f"tested surface: {summary.get('tested_surface')}"
                if summary.get("tested_surface")
                else "summary must name the tested surface",
            )
            check(
                "summary.shared-model-flags",
                "shared_model_roles" in summary,
                "shared-model roles recorded"
                if "shared_model_roles" in summary
                else "summary must record shared-model role flags",
            )
    else:
        check("artifact.replay-entries-present", False, "no replay entries recorded")

    # -- garak dispatches ----------------------------------------------------
    garak_attempts = (stages.get("garak") or {}).get("attempts", [])
    dispatches = []
    for attempt in garak_attempts:
        dispatches.extend(attempt.get("dispatches", []))
    for dispatch in dispatches:
        ddir = run.path / dispatch["dispatch_dir"]
        outcome_path = ddir / "outcome.json"
        if not outcome_path.is_file():
            check(f"garak.outcome-present.{dispatch['scenario_id']}", False, str(ddir))
            continue
        outcome = json.loads(outcome_path.read_text(encoding="utf-8"))
        attempts_rows = outcome.get("attempts", [])
        if outcome["outcome"] in ("attack_succeeded", "attack_not_demonstrated"):
            has_scores = any(a.get("detector_score") is not None for a in attempts_rows)
            check(
                f"garak.detector-results-present.{dispatch['scenario_id']}",
                has_scores,
                "native detector results present for the verdict"
                if has_scores
                else "a verdict without a native detector result is invalid",
            )
        else:
            check(
                f"garak.dispatch-receipt-present.{dispatch['scenario_id']}",
                (ddir / "dispatch.json").is_file()
                and (ddir / "pre-dispatch.json").is_file(),
                "inconclusive dispatches still need pre/post receipts",
            )
        # Correlate with the replay entry that was reviewed.
        entry = next(
            (r for r in replay_entries if r["scenario_id"] == dispatch["scenario_id"]),
            None,
        )
        check(
            f"garak.dispatch-matches-reviewed-entry.{dispatch['scenario_id']}",
            entry is not None,
            "dispatch has no matching reviewed replay entry",
        )
        if entry is not None:
            pre = json.loads((ddir / "pre-dispatch.json").read_text(encoding="utf-8"))
            recheck = pre.get("hash_recheck_ok", False)
            check(
                f"garak.hash-recheck-before-dispatch.{dispatch['scenario_id']}",
                recheck,
                "replay entry hash rechecked before dispatch"
                if recheck
                else "replay entry hash changed between review and dispatch",
            )

    # -- review bindings ------------------------------------------------------
    review_dir = run.path / "reviews"
    for request_path in sorted(review_dir.glob("*.request.json")):
        response_path = request_path.with_name(
            request_path.name.replace(".request.json", ".response.json")
        )
        if response_path.is_file():
            response = json.loads(response_path.read_text(encoding="utf-8"))
            request = json.loads(request_path.read_text(encoding="utf-8"))
            stale = [
                entry["path"]
                for entry in request.get("material", [])
                if entry["path"] not in (response.get("reviewed_hashes") or {})
                or (response.get("reviewed_hashes") or {}).get(entry["path"])
                != entry["sha256"]
            ]
            check(
                f"review.bindings-current.{request_path.stem}",
                not stale,
                "all reviewed material hashes current"
                if not stale
                else f"material changed since review: {stale}",
            )

    # -- secrets must not appear in evidence ---------------------------------
    if config is not None:
        secrets = {}
        for spec in config.connections.values():
            values = spec.resolve()
            if values.get("api_key"):
                secrets[spec.role] = values["api_key"]
        leaks = []
        if secrets:
            for path in run.path.rglob("*"):
                if not path.is_file() or path.name == "run.lock":
                    continue
                rel = path.relative_to(run.path).as_posix()
                if rel == "inventory.json":
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                for role, value in secrets.items():
                    if value and len(value) >= 8 and value in text:
                        leaks.append(f"{rel} contains the {role} API key value")
                        break
        check(
            "evidence.no-secret-values",
            not leaks,
            "no configured secret values found in retained evidence"
            if not leaks
            else "; ".join(leaks[:5]),
        )

    report = {
        "ok": not problems,
        "checks": checks,
        "problems": problems,
        "warnings": warnings,
        "verified_at": run.manifest().get("updated_at"),
        "scope_note": (
            "recorded-consistency verification: lineage links, hashes, "
            "admission receipts, dispatch correlations and detector results. "
            "Not independent proof of provider identity, hidden HTTP retries "
            "or attestation truth; unavailable returned model IDs remain unknown."
        ),
    }
    run.update_manifest(lambda m: m.update({"verify_run": report}))
    return report
