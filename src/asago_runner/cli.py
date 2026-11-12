"""Stage-oriented CLI for the Asago policy-to-Garak runner.

Commands print a machine-readable JSON outcome (final stdout line) and use
distinct exit codes so an incomplete stage can never be mistaken for success:

    0 completed · 4 completed-with-gaps · 2 needs-review · 3 blocked · 1 failed

Review gates persist a request file and return ``needs_review`` without a
live waiting process; approval binds to content hashes and is invalidated by
material change. The skill (SKILL.md) drives the same commands an independent
CLI caller can use.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Optional

import typer
import yaml
from typing_extensions import Annotated

from . import (
    BLOCKED,
    COMPLETED,
    COMPLETED_WITH_GAPS,
    FAILED,
    NEEDS_REVIEW,
    RUNNER_NAME,
    STATUS_EXIT_CODES,
    __version__,
)
from .config import ConfigError, RunConfig
from .evidence import RunDir, RunLockError, Stopwatch, atomic_write_json, utc_now_iso
from .hashing import sha256_file
from .intake import (
    IntakeError,
    effective_inputs,
    parse_receipts,
    prepare_conflict_review,
)
from .preflight import run_preflight
from .proc import quote_command
from .reviews import ReviewRequest, bind_material, write_review_response
from .telemetry import init_telemetry, stage_span

app = typer.Typer(
    name="asago-runner",
    help="Policy-to-Garak orchestration for the Asago component chain.",
    no_args_is_help=True,
    add_completion=False,
)

DEFAULT_CACHE_DIR = Path(".cache")
DEFAULT_GARAK_ENV = Path(__file__).resolve().parents[2] / "garak-env"


class Outcome:
    """Collect a command outcome; print JSON and exit with the right code."""

    def __init__(self, stage: str, run_dir: str):
        self.payload = {
            "runner": RUNNER_NAME,
            "runner_version": __version__,
            "stage": stage,
            "run_dir": run_dir,
        }

    def finish(self, status: str, **fields) -> typer.Exit:
        self.payload["status"] = status
        self.payload.update(fields)
        # Single-line JSON as the final stdout line: the machine contract.
        print(json.dumps(self.payload))
        raise typer.Exit(code=STATUS_EXIT_CODES.get(status, 1))


def _load_run(path: str) -> RunDir:
    try:
        return RunDir(path)
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _load_config(run: RunDir) -> RunConfig:
    config_path = run.path / "originals" / "run-config.yaml"
    try:
        return RunConfig.load(config_path, path_map=run.manifest().get("originals_map"))
    except ConfigError as exc:
        raise typer.BadParameter(f"run configuration error: {exc}") from exc


def _stage_record(run: RunDir, stage: str, **fields) -> dict:
    watch = Stopwatch()

    def mutate(manifest: dict) -> None:
        manifest["updated_at"] = utc_now_iso()
        stage_rec = manifest.setdefault("flow", {}).setdefault(stage, {})
        stage_rec.update(fields)

    run.update_manifest(mutate)
    return {"timing": watch.lap()}


# ---------------------------------------------------------------------------
# new-run
# ---------------------------------------------------------------------------


@app.command(name="new-run")
def new_run(
    config: Annotated[Path, typer.Option("--config", help="Run configuration YAML")],
    run_dir: Annotated[
        Optional[Path], typer.Option("--run-dir", help="Target run directory")
    ],
    cache_dir: Annotated[
        Path, typer.Option(help="Runner-managed cache directory")
    ] = DEFAULT_CACHE_DIR,
):
    """Create a run directory, snapshot config and copy original inputs."""
    try:
        cfg = RunConfig.load(config)
    except ConfigError as exc:
        raise typer.BadParameter(str(exc)) from exc
    target = run_dir or Path("runs") / f"run-{utc_now_iso().replace(':', '').replace('-', '')[:15]}"
    if target.exists():
        raise typer.BadParameter(f"{target} already exists")
    # Validate every referenced input exists before creating anything.
    missing = [str(p) for p in cfg.policy_paths() if not p.is_file()]
    for key in ("use_case_file", "profile_file", "qualification_facts_file"):
        path = cfg.resolved_path(key)
        if not path.is_file():
            missing.append(f"{key}: {path}")
    if not cfg.sssom_path().is_file():
        missing.append(f"sssom: {cfg.sssom_path()}")
    if missing:
        raise typer.BadParameter(
            "configuration references missing inputs: " + "; ".join(missing)
        )
    run = RunDir.create(target)

    # Copy originals: policies, system context, SSSOM, config itself.
    # The config-relative → run-dir mapping is recorded so later stages can
    # load the copied configuration and resolve the same inputs.
    originals = run.path / "originals"
    path_map: dict[str, str] = {}
    policy_copies = []
    for entry, path in zip(cfg.raw["policy"]["documents"], cfg.policy_paths()):
        dest = originals / "policies" / path.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)
        policy_copies.append(dest)
        path_map[entry["path"]] = str(dest)
    for key in ("use_case_file", "profile_file", "qualification_facts_file"):
        config_rel = cfg.raw["system"][key]
        src = cfg.resolved_path(key)
        dest = originals / "system" / src.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        path_map[config_rel] = str(dest)
    sssom_config_rel = cfg.raw["sssom"]["path"]
    sssom_src = cfg.sssom_path()
    (originals / "sssom").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(sssom_src, originals / "sssom" / sssom_src.name)
    path_map[sssom_config_rel] = str(originals / "sssom" / sssom_src.name)
    shutil.copyfile(cfg.source_path, originals / "run-config.yaml")

    import uuid

    run_id = uuid.uuid4().hex[:12]
    run.update_manifest(
        lambda m: m.update(
            {
                "schema_version": 1,
                "run_id": run_id,
                "label": (cfg.raw.get("run") or {}).get("label") or target.name,
                "operator": (cfg.raw.get("run") or {}).get("operator") or "unknown",
                "created_at": utc_now_iso(),
                "updated_at": utc_now_iso(),
                "runner_version": __version__,
                "status": "initialized",
                "config_snapshot": cfg.sanitized_snapshot(),
                "policy_originals": [run.rel(p) for p in policy_copies],
                "originals_map": path_map,
                "shared_model_roles": cfg.shared_model_roles(),
                "cache_dir": str(cache_dir.resolve()),
                "garak_env_dir": str(DEFAULT_GARAK_ENV.resolve()),
            }
        )
    )
    run.rebuild_inventory()
    outcome = Outcome("new-run", str(run.path))
    return outcome.finish(
        COMPLETED,
        run_id=run_id,
        policy_originals=[run.rel(p) for p in policy_copies],
        next_step="asago-runner preflight " + str(run.path),
    )


# ---------------------------------------------------------------------------
# preflight (and input-readiness review)
# ---------------------------------------------------------------------------


@app.command()
def preflight(
    run_dir: Annotated[str, typer.Argument(help="Run directory")],
    response: Annotated[
        Optional[Path], typer.Option(help="Review response file to record")
    ] = None,
    cache_dir: Annotated[Path, typer.Option()] = DEFAULT_CACHE_DIR,
    garak_env: Annotated[Path, typer.Option()] = DEFAULT_GARAK_ENV,
    skip_nexus_fetch: Annotated[bool, typer.Option()] = False,
):
    """LLM-free readiness checks; prepares the input-readiness review."""
    run = _load_run(run_dir)
    cfg = _load_config(run)
    with run.locked(f"preflight pid={__import__('os').getpid()}"):
        if response is not None:
            request = _request_for(run, "input-readiness")
            problems = _record_review(run, request, response)
            if problems:
                return Outcome("preflight", run_dir).finish(
                    NEEDS_REVIEW, review_problems=problems
                )
            _stage_record(run, "input_readiness_review", state="resolved")
            return Outcome("preflight", run_dir).finish(COMPLETED, review="resolved")

        report = run_preflight(
            run, cfg, cache_dir, garak_env, fetch_nexus=not skip_nexus_fetch
        )
        if not report["ok"]:
            return Outcome("preflight", run_dir).finish(
                BLOCKED, blockers=report["blockers"], checks=report["checks"]
            )
        # Prepare the input-readiness review request.
        material = bind_material(
            run,
            [(rel, "retained original input") for rel in _all_originals(run)],
        )
        request = ReviewRequest(
            kind="input-readiness",
            question=(
                "Approve the run inputs and configuration for extraction: "
                "policy documents, system context, SSSOM mapping, model "
                "connections (see data-flow destinations), scope and "
                "telemetry settings. Confirm the data-flow table shows only "
                "destinations you accept for this material."
            ),
            material=material,
            summary={
                "data_flow": report["data_flow"],
                "shared_model_roles": report["shared_model_roles"],
                "scope": report.get("scope"),
            },
            request_path=run.path / "reviews" / "input-readiness.request.json",
            response_path=run.path / "reviews" / "input-readiness.response.json",
        )
        request.write()
        _stage_record(run, "input_readiness_review", state="pending")
        return Outcome("preflight", run_dir).finish(
            NEEDS_REVIEW,
            review={
                "kind": "input-readiness",
                "request": run.rel(request.request_path),
                "question": request.question,
                "summary": request.summary,
            },
        )


# ---------------------------------------------------------------------------
# intake
# ---------------------------------------------------------------------------


@app.command()
def intake(
    run_dir: Annotated[str, typer.Argument(help="Run directory")],
    response: Annotated[
        Optional[Path], typer.Option(help="Conflict review response file")
    ] = None,
):
    """Native parse receipts; conflict review for multi-document input."""
    run = _load_run(run_dir)
    cfg = _load_config(run)
    with run.locked(f"intake pid={__import__('os').getpid()}"):
        policy_paths = [run.path / rel for rel in run.manifest()["policy_originals"]]
        receipts = parse_receipts(run, policy_paths, ocr=cfg.ocr)
        failed = [r for r in receipts if r.status != "ok"]
        if failed:
            return Outcome("intake", run_dir).finish(
                BLOCKED,
                blockers=[
                    f"{Path(r.source).name}: {r.error or r.status}" for r in failed
                ],
                receipts=[r.as_dict() for r in receipts],
            )
        if len(receipts) < 2:
            paths, mode, record = effective_inputs(run, receipts, None)
            _stage_record(
                run,
                "effective_inputs",
                mode=mode,
                paths=[run.rel(p) for p in paths],
                record=record,
            )
            return Outcome("intake", run_dir).finish(
                COMPLETED,
                receipts=[r.as_dict() for r in receipts],
                effective_mode=mode,
            )
        if response is not None:
            request = _request_for(run, "policy-conflict")
            problems = _record_review(run, request, response)
            if problems:
                return Outcome("intake", run_dir).finish(
                    NEEDS_REVIEW, review_problems=problems
                )
            conflict_response = json.loads(Path(response).read_text(encoding="utf-8"))
            try:
                paths, mode, rec = effective_inputs(run, receipts, conflict_response)
            except IntakeError as exc:
                return Outcome("intake", run_dir).finish(BLOCKED, blockers=[str(exc)])
            _stage_record(
                run,
                "effective_inputs",
                mode=mode,
                paths=[run.rel(p) for p in paths],
                record=rec,
            )
            return Outcome("intake", run_dir).finish(
                COMPLETED,
                receipts=[r.as_dict() for r in receipts],
                effective_mode=mode,
            )
        # Prepare the conflict review request.
        request_payload = prepare_conflict_review(run, receipts)
        request = ReviewRequest(
            kind="policy-conflict",
            question=request_payload["question"],
            material=request_payload["material"],
            summary={"documents": [Path(r.source).name for r in receipts]},
            request_path=run.path / "reviews" / "policy-conflict.request.json",
            response_path=run.path / "reviews" / "policy-conflict.response.json",
            extras={
                "note": (
                    "conflict detection is agent-assisted and interpretive; it "
                    "cannot certify that every disagreement was found"
                )
            },
        )
        request.write()
        _stage_record(run, "conflict_review", state="pending")
        return Outcome("intake", run_dir).finish(
            NEEDS_REVIEW,
            receipts=[r.as_dict() for r in receipts],
            review={
                "kind": "policy-conflict",
                "request": run.rel(request.request_path),
                "question": request.question,
            },
        )


# ---------------------------------------------------------------------------
# map (Policy Mapper)
# ---------------------------------------------------------------------------


@app.command()
def map(
    run_dir: Annotated[str, typer.Argument(help="Run directory")],
    no_llm: Annotated[
        bool, typer.Option("--no-llm", help="Model-free IR-only mode (E2)")
    ] = False,
):
    """Run the Policy Mapper on this run's effective policy inputs."""
    from .adapters.mapper import run_mapper

    run = _load_run(run_dir)
    cfg = _load_config(run)
    with run.locked(f"map pid={__import__('os').getpid()}"):
        flow = run.manifest().get("flow", {})
        effective = flow.get("effective_inputs") or {}
        if not effective.get("paths"):
            return Outcome("map", run_dir).finish(
                BLOCKED,
                blockers=["run intake first: effective inputs are not resolved"],
            )
        if not no_llm and flow.get("input_readiness_review", {}).get("state") != "resolved":
            return Outcome("map", run_dir).finish(
                BLOCKED,
                blockers=["input-readiness review is not resolved; run preflight --response"],
            )
        cache = Path(run.manifest().get("cache_dir", DEFAULT_CACHE_DIR))
        from .nexus import ensure_nexus_cache

        nexus = ensure_nexus_cache(cache)
        policy_paths = [run.path / p for p in effective["paths"]]
        attempt_id, attempt_dir = run.new_attempt_dir("policy-mapper")
        init_telemetry()
        with stage_span(run.manifest()["run_id"], "policy-mapper", attempt_id):
            run.record_stage_attempt(
                "policy-mapper",
                attempt_id,
                {"attempt_id": attempt_id, "started_at": utc_now_iso(), "no_llm_mode": no_llm},
            )
            try:
                result = run_mapper(
                    run, cfg, attempt_dir, policy_paths, Path(nexus.cache_dir), no_llm=no_llm
                )
            except Exception as exc:  # noqa: BLE001
                run.record_stage_outcome(
                    "policy-mapper", attempt_id, {"status": FAILED, "error": str(exc)}
                )
                return Outcome("map", run_dir).finish(FAILED, error=str(exc))
            record = {
                "status": result.status,
                "attempt_id": attempt_id,
                "attempt_dir": run.rel(attempt_dir),
                "command": result.command,
                "returncode": result.proc.returncode if result.proc else None,
                "timed_out": result.proc.timed_out if result.proc else None,
                "accounting": result.accounting or None,
                "completed_at": utc_now_iso(),
            }
            run.record_stage_outcome("policy-mapper", attempt_id, record)
            run.rebuild_inventory()
        if result.status in (COMPLETED, COMPLETED_WITH_GAPS) and not no_llm:
            _stage_record(
                run,
                "mapper_output",
                extraction=str(
                    (attempt_dir / "risk-extraction.json").relative_to(run.path)
                ),
            )
        payload = {
            "attempt": attempt_id,
            "command": result.command,
            "accounting": result.accounting,
        }
        return Outcome("map", run_dir).finish(
            result.status,
            blockers=result.blockers,
            gaps=result.gaps,
            **payload,
        )


# ---------------------------------------------------------------------------
# scenarios
# ---------------------------------------------------------------------------


@app.command()
def scenarios(
    run_dir: Annotated[str, typer.Argument(help="Run directory")],
):
    """Projection preflight + taxonomy/risk scenario generation."""
    from .adapters.scenarios import (
        filter_risk_extraction,
        handoff_receipts,
        read_run_manifest,
        resolve_admitted,
        run_generate,
        run_projection_preflight,
    )

    run = _load_run(run_dir)
    cfg = _load_config(run)
    with run.locked(f"scenarios pid={__import__('os').getpid()}"):
        flow = run.manifest().get("flow", {})
        extraction_rel = flow.get("mapper_output", {}).get("extraction")
        if not extraction_rel:
            return Outcome("scenarios", run_dir).finish(
                BLOCKED,
                blockers=[
                    "run map first: no grounded mapper output recorded. Note: "
                    "--no-llm (IR-only) mapper output has "
                    "grounding_confidence='ungrounded', which the Scenario "
                    "Generator's native RiskCard contract rejects; only the "
                    "grounded live mapper path advances the pipeline"
                ],
            )
        extraction_path = run.path / extraction_rel

        attempt_id, attempt_dir = run.new_attempt_dir("scenario-generator")
        run.record_stage_attempt(
            "scenario-generator",
            attempt_id,
            {"attempt_id": attempt_id, "started_at": utc_now_iso()},
        )
        init_telemetry()
        with stage_span(run.manifest()["run_id"], "scenario-generator", attempt_id):
            # Explicit risk selection: recorded input adaptation.
            if cfg.selected_risk_ids:
                extraction_path, selection = filter_risk_extraction(
                    run, extraction_path, cfg.selected_risk_ids
                )
            else:
                selection = None

            use_case = run.path / "originals" / "system" / cfg.resolved_path("use_case_file").name
            profile = run.path / "originals" / "system" / cfg.resolved_path("profile_file").name
            facts_src = cfg.resolved_path("qualification_facts_file")
            facts = run.path / "originals" / "system" / facts_src.name
            sssom = run.path / "originals" / "sssom" / cfg.sssom_path().name

            try:
                preflight_outcome = run_projection_preflight(
                    cfg,
                    attempt_dir,
                    use_case_file=use_case,
                    risk_extraction=extraction_path,
                    sssom=sssom,
                    profile=profile,
                    qualification_facts=facts if facts.is_file() else None,
                    facts_template=attempt_dir / "facts-template.yaml",
                )
            except Exception as exc:  # noqa: BLE001
                run.record_stage_outcome(
                    "scenario-generator", attempt_id, {"status": FAILED, "error": str(exc)}
                )
                return Outcome("scenarios", run_dir).finish(FAILED, error=str(exc))
            atomic_write_json(
                attempt_dir / "projection-preflight.json", preflight_outcome
            )
            unresolved = _preflight_unresolved(preflight_outcome)
            if unresolved:
                run.record_stage_outcome(
                    "scenario-generator",
                    attempt_id,
                    {"status": NEEDS_REVIEW, "preflight_unresolved": unresolved},
                )
                return Outcome("scenarios", run_dir).finish(
                    NEEDS_REVIEW,
                    review={
                        "kind": "qualification-facts",
                        "unresolved": unresolved,
                        "facts_template": run.rel(attempt_dir / "facts-template.yaml"),
                        "note": (
                            "fill the requested facts template with real "
                            "readings; absent/unknown/contradictory facts must "
                            "be resolved, not invented"
                        ),
                    },
                )

            output_dir = run.path / "stages" / "scenario-generator" / attempt_id / "runs"
            proc, command = run_generate(
                cfg,
                attempt_dir,
                use_case_file=use_case,
                risk_extraction=extraction_path,
                sssom=sssom,
                profile=profile,
                qualification_facts=facts if facts.is_file() else None,
                output_dir=output_dir,
            )
            atomic_write_json(
                attempt_dir / "attempt.json",
                {
                    "component": "asago-scenario-generator",
                    "command": command,
                    "returncode": proc.returncode,
                    "timed_out": proc.timed_out,
                },
            )
            if proc.timed_out:
                run.record_stage_outcome(
                    "scenario-generator",
                    attempt_id,
                    {"status": FAILED, "error": "stage deadline exceeded"},
                )
                return Outcome("scenarios", run_dir).finish(
                    FAILED, error="scenario generation exceeded the stage deadline"
                )

            # Resolve the run directory: newest child under runs/.
            try:
                scenario_run_dir = _latest_scenario_run(output_dir)
                manifest = read_run_manifest(scenario_run_dir)
                admitted, quarantined = resolve_admitted(scenario_run_dir)
            except (FileNotFoundError, RuntimeError) as exc:
                run.record_stage_outcome(
                    "scenario-generator", attempt_id, {"status": FAILED, "error": str(exc)}
                )
                return Outcome("scenarios", run_dir).finish(FAILED, error=str(exc))

            handoff_dir = attempt_dir / "handoff"
            receipts = handoff_receipts(run, admitted, handoff_dir)
            inventory_summary = {
                "admitted": len([r for r in admitted if r["role"] == "scenario_yaml"]),
                "quarantined": len(quarantined),
                "manifest_status": manifest.get("status"),
            }
            record = {
                "status": COMPLETED if receipts else BLOCKED,
                "attempt_id": attempt_id,
                "scenario_run_dir": run.rel(scenario_run_dir),
                "inventory_summary": inventory_summary,
                "selection": selection,
                "completed_at": utc_now_iso(),
            }
            run.record_stage_outcome("scenario-generator", attempt_id, record)
            run.rebuild_inventory()
            if not receipts:
                return Outcome("scenarios", run_dir).finish(
                    BLOCKED,
                    blockers=[
                        "zero admitted scenarios with a sibling .feature file; "
                        "an incomplete evaluation, not a successful end-to-end result"
                    ],
                    inventory_summary=inventory_summary,
                )
            _stage_record(
                run,
                "scenario_handoff",
                receipts=str((handoff_dir / "handoff-receipts.json").relative_to(run.path)),
                scenario_run_dir=run.rel(scenario_run_dir),
            )
            return Outcome("scenarios", run_dir).finish(
                COMPLETED_WITH_GAPS if quarantined else COMPLETED,
                inventory_summary=inventory_summary,
                admitted=[r["scenario_id"] for r in receipts],
                handoff=run.rel(handoff_dir / "handoff-receipts.json"),
                gaps=[
                    f"{len(quarantined)} quarantined candidates retained in the "
                    "native quarantine inventory"
                ]
                if quarantined
                else [],
            )


def _preflight_unresolved(preflight_outcome: dict) -> list[dict]:
    """Extract unresolved fact conditions from the native preflight JSON."""
    unresolved = []
    for key in ("required_facts", "facts", "unresolved"):
        for item in preflight_outcome.get(key, []) or []:
            if isinstance(item, dict) and item.get("status") in (
                "absent",
                "unknown",
                "stale",
                "contradictory",
            ):
                unresolved.append(item)
    return unresolved


def _latest_scenario_run(output_dir: Path) -> Path:
    children = sorted(p for p in output_dir.iterdir() if p.is_dir())
    if not children:
        raise FileNotFoundError(f"no scenario run directory under {output_dir}")
    return children[-1]


# ---------------------------------------------------------------------------
# artifacts + replay entries
# ---------------------------------------------------------------------------


@app.command()
def artifacts(
    run_dir: Annotated[str, typer.Argument(help="Run directory")],
):
    """Transport eligibility + Artifact Generator + replay entries."""
    from .adapters.artifacts import (
        adapted_scenario,
        eligibility_for_batch,
        process_manifest,
        run_artifact_generator,
        write_replay_entries,
    )

    run = _load_run(run_dir)
    cfg = _load_config(run)
    with run.locked(f"artifacts pid={__import__('os').getpid()}"):
        flow = run.manifest().get("flow", {})
        handoff_rel = flow.get("scenario_handoff", {}).get("receipts")
        if not handoff_rel:
            return Outcome("artifacts", run_dir).finish(
                BLOCKED, blockers=["run scenarios first: no handoff receipts"]
            )
        handoff_receipts = json.loads((run.path / handoff_rel).read_text(encoding="utf-8"))

        attempt_id, attempt_dir = run.new_attempt_dir("artifact-generator")
        run.record_stage_attempt(
            "artifact-generator",
            attempt_id,
            {"attempt_id": attempt_id, "started_at": utc_now_iso()},
        )
        init_telemetry()
        with stage_span(run.manifest()["run_id"], "artifact-generator", attempt_id):
            # Model-free eligibility before any artifact model call.
            eligibility_pairs = eligibility_for_batch(handoff_receipts)
            atomic_write_json(
                attempt_dir / "eligibility.json",
                [
                    {
                        "scenario_id": eligibility.scenario_id,
                        "eligible": eligibility.eligible,
                        "surface": eligibility.surface,
                        "reason": eligibility.reason,
                        "basis": eligibility.basis,
                    }
                    for _, eligibility in eligibility_pairs
                ],
            )
            eligible = [(r, e) for r, e in eligibility_pairs if e.eligible]
            excluded = [
                f"{e.scenario_id}: {e.reason}" for _, e in eligibility_pairs if not e.eligible
            ]
            if not eligible:
                run.record_stage_outcome(
                    "artifact-generator",
                    attempt_id,
                    {"status": BLOCKED, "excluded": excluded},
                )
                return Outcome("artifacts", run_dir).finish(
                    BLOCKED,
                    blockers=["no admitted scenario has a supported transport"],
                    excluded=excluded,
                )

            # Deterministic selection before model calls, bounded by scope.
            selected = eligible[: cfg.max_artifacts]

            # Provenance-backed adaptations where required.
            adapted_dir = attempt_dir / "adapted-scenarios"
            scenario_paths = []
            for receipt, eligibility in selected:
                if eligibility.adaptation:
                    scenario_paths.append(adapted_scenario(run, receipt, eligibility, adapted_dir))
                else:
                    scenario_paths.append(Path(receipt["yaml"]))

            output_dir = attempt_dir / "runs"
            proc, command = run_artifact_generator(
                cfg, attempt_dir, scenario_paths, output_dir
            )
            if proc.timed_out or proc.returncode != 0:
                run.record_stage_outcome(
                    "artifact-generator",
                    attempt_id,
                    {
                        "status": FAILED,
                        "error": (
                            "deadline exceeded" if proc.timed_out
                            else f"exit code {proc.returncode}"
                        ),
                        "command": command,
                    },
                )
                return Outcome("artifacts", run_dir).finish(
                    FAILED,
                    error="artifact generation failed; see attempt stderr",
                    attempt=attempt_id,
                )

            receipts_by_scenario = {r["scenario_id"]: r for r in handoff_receipts}
            candidates, gaps, blockers = process_manifest(
                attempt_dir, output_dir, selected, receipts_by_scenario
            )
            replay_entries, replay_gaps = write_replay_entries(run, attempt_dir, candidates, cfg)
            gaps.extend(replay_gaps)

            record = {
                "status": COMPLETED if replay_entries else BLOCKED,
                "attempt_id": attempt_id,
                "command": command,
                "candidate_count": len(candidates),
                "replay_entries": replay_entries,
                "excluded": excluded,
                "completed_at": utc_now_iso(),
            }
            run.record_stage_outcome("artifact-generator", attempt_id, record)
            run.rebuild_inventory()
            if not replay_entries:
                return Outcome("artifacts", run_dir).finish(
                    BLOCKED,
                    blockers=["no validated artifact with a matching transport"],
                    gaps=gaps,
                    excluded=excluded,
                )
            _stage_record(
                run,
                "replay_entries",
                attempt=str(attempt_dir.relative_to(run.path)),
                entries=replay_entries,
            )
            status = COMPLETED_WITH_GAPS if (gaps or excluded) else COMPLETED
            return Outcome("artifacts", run_dir).finish(
                status,
                attempt=attempt_id,
                replay_entries=replay_entries,
                excluded=excluded,
                gaps=gaps,
            )


# ---------------------------------------------------------------------------
# replay-review (test plan)
# ---------------------------------------------------------------------------


@app.command(name="replay-review")
def replay_review(
    run_dir: Annotated[str, typer.Argument(help="Run directory")],
    response: Annotated[
        Optional[Path], typer.Option(help="Review response file to record")
    ] = None,
):
    """Prepare (or record) the generated-test-plan review before evaluation."""
    run = _load_run(run_dir)
    with run.locked(f"replay-review pid={__import__('os').getpid()}"):
        flow = run.manifest().get("flow", {})
        entries = flow.get("replay_entries", {}).get("entries")
        if not entries:
            return Outcome("replay-review", run_dir).finish(
                BLOCKED, blockers=["run artifacts first: no replay entries"]
            )
        if response is not None:
            request = _request_for(run, "test-plan")
            problems = _record_review(run, request, response)
            if problems:
                return Outcome("replay-review", run_dir).finish(
                    NEEDS_REVIEW, review_problems=problems
                )
            _stage_record(run, "test_plan_review", state="resolved")
            return Outcome("replay-review", run_dir).finish(COMPLETED, review="resolved")

        manifest = run.manifest()
        cfg = _load_config(run)
        # Resolve connections live so the reviewed target/judge identities are
        # what evaluation will actually use (the intake snapshot may predate
        # recorded model changes).
        target = cfg.connections["target"].sanitized()
        judge = cfg.connections["judge"].sanitized()
        material = bind_material(
            run,
            [(e["entry_path"].replace(str(run.path) + "/", ""), "replay entry (exact evaluated input)")
             for e in entries]
            + [(e["meta_path"].replace(str(run.path) + "/", ""), "replay metadata (parents, schema derivations)")
               for e in entries],
        )
        request = ReviewRequest(
            kind="test-plan",
            question=(
                "Approve the generated test plan for target evaluation. This "
                "binds the exact replay batch Garak will receive: messages, "
                "effective tools/tool_choice, composed judge criteria, attack "
                "placement, target/judge endpoints and models, derived tool "
                "schemas (test assumptions, not confirmed deployed "
                "interfaces), and native retry limitations. Approval covers "
                "the full batch; partial coverage items are listed with "
                "their omitted behavior."
            ),
            material=material,
            summary={
                "entries": [
                    {
                        "scenario_id": e["scenario_id"],
                        "surface": e["surface"],
                        "entry_sha256": e["entry_sha256"],
                    }
                    for e in entries
                ],
                "target": target,
                "judge": judge,
                "shared_model_roles": cfg.shared_model_roles(),
                "retry_disclosure": (
                    "Garak/SDK internal retries are not individually bounded; "
                    "the runner adds no replay of its own; the parent deadline "
                    "bounds wall-clock only and does not cancel requests "
                    "already accepted by the endpoint"
                ),
            },
            request_path=run.path / "reviews" / "test-plan.request.json",
            response_path=run.path / "reviews" / "test-plan.response.json",
        )
        request.write()
        _stage_record(run, "test_plan_review", state="pending")
        return Outcome("replay-review", run_dir).finish(
            NEEDS_REVIEW,
            review={
                "kind": "test-plan",
                "request": run.rel(request.request_path),
                "summary": request.summary,
            },
        )


# ---------------------------------------------------------------------------
# evaluate (Garak)
# ---------------------------------------------------------------------------


@app.command()
def evaluate(
    run_dir: Annotated[str, typer.Argument(help="Run directory")],
    garak_env: Annotated[Path, typer.Option()] = DEFAULT_GARAK_ENV,
):
    """Evaluate the reviewed replay entries with Garak, one per subprocess."""
    from .adapters.garak_eval import evaluate_entry, garak_python

    run = _load_run(run_dir)
    cfg = _load_config(run)
    with run.locked(f"evaluate pid={__import__('os').getpid()}"):
        flow = run.manifest().get("flow", {})
        entries = flow.get("replay_entries", {}).get("entries")
        if not entries:
            return Outcome("evaluate", run_dir).finish(
                BLOCKED, blockers=["run artifacts first: no replay entries"]
            )
        if flow.get("test_plan_review", {}).get("state") != "resolved":
            return Outcome("evaluate", run_dir).finish(
                BLOCKED,
                blockers=["test-plan review is not resolved; run replay-review --response"],
            )
        try:
            garak_python(garak_env)
        except FileNotFoundError as exc:
            return Outcome("evaluate", run_dir).finish(BLOCKED, blockers=[str(exc)])

        attempt_id, attempt_dir = run.new_attempt_dir("garak")
        run.record_stage_attempt(
            "garak", attempt_id, {"attempt_id": attempt_id, "started_at": utc_now_iso()}
        )
        init_telemetry()
        results = []
        with stage_span(run.manifest()["run_id"], "garak", attempt_id):
            for entry in entries:
                with stage_span(
                    run.manifest()["run_id"], "garak", attempt_id,
                    {"scenario": entry["scenario_id"]},
                ):
                    result = evaluate_entry(
                        run,
                        cfg,
                        replay_entry=entry,
                        garak_env_dir=garak_env,
                        dispatch_root=attempt_dir,
                    )
                    results.append(result)
            dispatches = [
                {
                    "scenario_id": r.scenario_id,
                    "outcome": r.outcome,
                    "reason": r.reason,
                    "judge_confidence": r.judge_confidence,
                    "detector_score": r.detector_score,
                    "surface": next(
                        (e["surface"] for e in entries if e["scenario_id"] == r.scenario_id),
                        None,
                    ),
                    "dispatch_dir": run.rel(r.dispatch_dir),
                    "returncode": r.proc.returncode if r.proc else None,
                    "timed_out": r.proc.timed_out if r.proc else None,
                }
                for r in results
            ]
            usable = [
                r for r in results if r.outcome in ("attack_succeeded", "attack_not_demonstrated")
            ]
            status = COMPLETED if usable else (COMPLETED_WITH_GAPS if results else BLOCKED)
            run.record_stage_outcome(
                "garak",
                attempt_id,
                {
                    "status": status,
                    "dispatches": dispatches,
                    "completed_at": utc_now_iso(),
                },
            )
            run.rebuild_inventory()
        gaps = [
            f"{r.scenario_id}: {r.outcome} ({r.reason})" for r in results if r.outcome == "inconclusive"
        ]
        return Outcome("evaluate", run_dir).finish(
            status,
            attempt=attempt_id,
            evaluations=dispatches,
            gaps=gaps,
        )


# ---------------------------------------------------------------------------
# report / verify-run / status / respond
# ---------------------------------------------------------------------------


@app.command()
def report(run_dir: Annotated[str, typer.Argument(help="Run directory")]):
    """Derive summary.json and render the offline HTML overview."""
    from .reporting import build_summary, render_html

    run = _load_run(run_dir)
    with run.locked(f"report pid={__import__('os').getpid()}"):
        summary = build_summary(run)
        html_path = render_html(run, summary)
        run.rebuild_inventory()
        return Outcome("report", run_dir).finish(
            COMPLETED,
            summary=run.rel(run.path / "reports" / "summary.json"),
            html=run.rel(html_path),
        )


@app.command(name="verify-run")
def verify_run_cmd(run_dir: Annotated[str, typer.Argument(help="Run directory")]):
    """Model-free verification of the retained live output."""
    from .verify import verify_run

    run = _load_run(run_dir)
    cfg = _load_config(run)
    with run.locked(f"verify pid={__import__('os').getpid()}"):
        try:
            report = verify_run(run, cfg)
        except Exception as exc:  # noqa: BLE001
            return Outcome("verify-run", run_dir).finish(FAILED, error=str(exc))
        run.rebuild_inventory()
        status = COMPLETED if report["ok"] else FAILED
        return Outcome("verify-run", run_dir).finish(
            status, problems=report["problems"], checks=report["checks"]
        )


@app.command()
def status(run_dir: Annotated[str, typer.Argument(help="Run directory")]):
    """Print the run's current machine-readable state."""
    run = _load_run(run_dir)
    manifest = run.manifest()
    return Outcome("status", run_dir).finish(
        COMPLETED,
        run_id=manifest.get("run_id"),
        stages=manifest.get("stages", {}),
        flow=manifest.get("flow", {}),
    )


@app.command()
def respond(
    request_path: Annotated[Path, typer.Argument(help="Review request file")],
    decision: Annotated[str, typer.Option(help="Decision value")],
    actor: Annotated[str, typer.Option(help="Actor label")] = "user",
    notes: Annotated[str, typer.Option(help="Visible notes recorded with the decision")] = "",
    clarification: Annotated[
        Optional[str], typer.Option(help="Visible clarification exchange (recorded verbatim)")
    ] = None,
    reconciliation_file: Annotated[
        Optional[Path], typer.Option(help="Reconciliation spec for policy-conflict")
    ] = None,
):
    """Write a review response file for a request (agent/human convenience)."""
    extras = {}
    if reconciliation_file is not None:
        extras["reconciliation"] = yaml.safe_load(
            reconciliation_file.read_text(encoding="utf-8")
        )
    clarifications = []
    if clarification:
        clarifications.append({"exchange": clarification})
    response_path = write_review_response(
        request_path,
        decision=decision,
        actor=actor,
        visible_notes=notes,
        clarifications=clarifications,
        extras=extras,
    )
    print(json.dumps({"response": str(response_path)}))
    return typer.Exit(code=0)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _all_originals(run: RunDir) -> list[str]:
    originals = []
    for path in sorted((run.path / "originals").rglob("*")):
        if path.is_file():
            originals.append(str(path.relative_to(run.path)))
    return originals


def _request_for(run: RunDir, kind: str) -> ReviewRequest:
    """Reconstruct a persisted request for response validation."""
    request_path = run.path / "reviews" / f"{kind}.request.json"
    if not request_path.is_file():
        raise typer.BadParameter(f"no {kind} review request at {request_path}")
    data = json.loads(request_path.read_text(encoding="utf-8"))
    return ReviewRequest(
        kind=data["kind"],
        question=data.get("question", ""),
        material=data.get("material", []),
        summary=data.get("summary", {}),
        request_path=request_path,
        response_path=request_path.with_name(data.get("response_file", "response.json")),
    )


def _record_review(run: RunDir, request: ReviewRequest, response_path: Path) -> list[str]:
    """Validate and record a review response; returns problems."""
    if not response_path.is_file():
        return [f"response file not found: {response_path}"]
    response = json.loads(response_path.read_text(encoding="utf-8"))
    problems = request.validate_response(response)
    if not problems:
        # Staleness: the request's recorded hashes must match the live files.
        for entry in request.material:
            live = run.path / entry["path"]
            from .hashing import sha256_file as _sha

            if not live.is_file():
                problems.append(f"reviewed material is missing: {entry['path']}")
            elif _sha(live) != entry["sha256"]:
                problems.append(
                    f"reviewed material changed since the request: {entry['path']}; "
                    "re-review is required"
                )
    if problems:
        return problems
    run.append_decision(
        {
            "category": request.kind,
            "actor": {"label": response.get("actor", "user"), "identity_source": "review-file"},
            "question": request.question,
            "evidence": request.material,
            "response": response.get("decision"),
            "visible_notes": response.get("visible_notes", ""),
            "clarifications": response.get("clarifications", []),
            "resolution": response.get("decision"),
            "scope": [entry["path"] for entry in request.material],
            "reviewed_hashes": response.get("reviewed_hashes", {}),
            "state": "resolved",
            **({"raw_response": {k: v for k, v in response.items() if k != "reviewed_hashes"}}
               if request.kind == "policy-conflict" else {}),
        }
    )
    return []


if __name__ == "__main__":
    app()
