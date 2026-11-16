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
from .evidence import RunDir, atomic_write_json, utc_now_iso
from .hashing import sha256_file
from .intake import (
    IntakeError,
    effective_inputs,
    parse_receipts,
    prepare_conflict_review,
)
from .preflight import run_preflight
from .reviews import ReviewRequest, bind_material, write_review_response
from .telemetry import init_telemetry, stage_span

app = typer.Typer(
    name="asago-runner",
    help="Run the Asago pipeline: policy documents to evaluated results.",
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


def _require_built_subject(run: RunDir, stage: str, run_dir: str) -> Outcome | None:
    """Design-time runs stop after the Scenario Generator by design."""
    cfg = _load_config(run)
    if cfg.subject == "proposed":
        return Outcome(stage, run_dir).finish(
            BLOCKED,
            blockers=[
                "this is a design-time run (run.subject: proposed): the "
                "described agent is not built, so there is nothing to "
                "evaluate. The run deliberately stops after the Scenario "
                "Generator and reports the threat picture for the proposed "
                "design. To evaluate, build the system and start a new run "
                "with run.subject: built plus a target endpoint."
            ],
        )
    return None


def _stage_record(run: RunDir, stage: str, **fields) -> None:
    def mutate(manifest: dict) -> None:
        manifest["updated_at"] = utc_now_iso()
        stage_rec = manifest.setdefault("flow", {}).setdefault(stage, {})
        stage_rec.update(fields)

    run.update_manifest(mutate)


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------


@app.command()
def plan(
    subject: Annotated[
        str,
        typer.Option(
            "--subject",
            help="Which journey to print: 'built' (full chain) or 'proposed' "
            "(design-time: stops after the Scenario Generator)",
        ),
    ] = "built",
):
    """Print the canonical welcome plan — deterministic, identical every run.

    The skill must quote this verbatim (or translate it faithfully, keeping
    the tags and order) instead of composing its own plan. No run directory
    is needed; the plan is the same for every user and every session.
    """
    from .reporting import render_plan

    if subject not in ("built", "proposed"):
        raise typer.BadParameter("--subject must be 'built' or 'proposed'")
    print(render_plan(subject))
    return typer.Exit(code=0)


# ---------------------------------------------------------------------------
# model-options
# ---------------------------------------------------------------------------


@app.command(name="model-options")
def model_options():
    """Describe model connections available in this agent's environment.

    Detection only: nothing is selected, no secret value is printed, and
    compatibility is not assumed. The skill presents the result as an
    OPTION alongside the user's own choice.
    """
    from .model_options import detect_model_options, render_model_options

    detected = detect_model_options()
    print(render_model_options(detected))
    outcome = Outcome("model-options", "")
    return outcome.finish(COMPLETED, **detected)


# ---------------------------------------------------------------------------
# new-run
# ---------------------------------------------------------------------------


@app.command(name="new-run")
def new_run(
    config: Annotated[Path, typer.Option("--config", help="Run configuration YAML")],
    run_dir: Annotated[
        Optional[Path],
        typer.Option(
            "--run-dir",
            help="Target run directory (omit to create an isolated run under "
            "the runs root, outside the repository)",
        ),
    ] = None,
    cache_dir: Annotated[
        Path, typer.Option(help="Runner-managed cache directory")
    ] = DEFAULT_CACHE_DIR,
    runs_root: Annotated[
        Optional[Path],
        typer.Option(
            "--runs-root",
            help="Root for new runs when --run-dir is not given (default "
            "~/.asago/runs, or $ASAGO_RUNNER_RUNS_ROOT). Runs live outside "
            "the repository so each assessment is isolated from prior runs.",
        ),
    ] = None,
):
    """Create a run directory, snapshot config and copy original inputs."""
    from .paths import default_runs_root, sanitize_run_name

    try:
        cfg = RunConfig.load(config)
    except ConfigError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if run_dir is not None:
        target = run_dir
    else:
        root = (runs_root or default_runs_root()).resolve()
        label = sanitize_run_name((cfg.raw.get("run") or {}).get("label"))
        name = label or f"run-{utc_now_iso().replace(':', '').replace('-', '')[:15]}"
        target = root / name
        if target.exists():
            # Same label run before: keep it isolated, don't touch it.
            target = root / f"{name}-{utc_now_iso().replace(':', '').replace('-', '')[:15]}"
    # Resolve before anything is recorded: a relative --run-dir would
    # otherwise put CWD-relative paths into originals_map, which later
    # commands (run from other directories) cannot resolve.
    target = target.resolve()
    if target.exists():
        raise typer.BadParameter(f"{target} already exists")
    # Validate every referenced input exists before creating anything.
    missing = [str(p) for p in cfg.policy_paths() if not p.is_file()]
    for key in ("use_case_file", "profile_file", "qualification_facts_file"):
        if not cfg.raw["system"].get(key):
            continue  # profile/facts optional: Stage-1 inference runs instead
        path = cfg.resolved_path(key)
        if not path.is_file():
            missing.append(f"{key}: {path}")
    if not cfg.sssom_path().is_file():
        missing.append(f"sssom: {cfg.sssom_path()}")
    if cfg.tools_schema_file:
        schema_path = cfg._resolve(cfg.tools_schema_file)
        if not schema_path.is_file():
            missing.append(f"tools_schema_file: {schema_path}")
    if missing:
        raise typer.BadParameter(
            "configuration references missing inputs: " + "; ".join(missing)
        )

    # Plan every copy up-front so duplicate destinations are rejected
    # BEFORE anything is written. Two inputs sharing a basename (e.g. two
    # policies both called p.md) would otherwise silently overwrite each
    # other and share one path_map entry.
    originals_root = target / "originals"
    policy_rels = {entry["path"] for entry in cfg.raw["policy"]["documents"]}
    planned: list[tuple[str, Path, Path]] = []  # (config_rel, source, dest)
    for entry, path in zip(cfg.raw["policy"]["documents"], cfg.policy_paths()):
        planned.append((entry["path"], path, originals_root / "policies" / path.name))
    for key in ("use_case_file", "profile_file", "qualification_facts_file"):
        config_rel = cfg.raw["system"].get(key)
        if not config_rel:
            continue  # optional input: not supplied, not copied
        src = cfg.resolved_path(key)
        planned.append((config_rel, src, originals_root / "system" / src.name))
    sssom_src = cfg.sssom_path()
    planned.append(
        (cfg.raw["sssom"]["path"], sssom_src, originals_root / "sssom" / sssom_src.name)
    )
    if cfg.tools_schema_file:
        planned.append(
            (
                cfg.tools_schema_file,
                cfg._resolve(cfg.tools_schema_file),
                originals_root / "tool-schemas" / cfg._resolve(cfg.tools_schema_file).name,
            )
        )
    destinations: dict[Path, str] = {}
    for config_rel, _src, dest in planned:
        if dest in destinations:
            raise typer.BadParameter(
                "two inputs map to the same retained file "
                f"{dest.relative_to(target)} ({destinations[dest]!r} and "
                f"{config_rel!r}); rename one so each retained original is "
                "distinct"
            )
        destinations[dest] = config_rel

    run = RunDir.create(target)

    # Copy originals: policies, system context, SSSOM, tool schemas, config.
    # The config-relative → run-dir mapping is recorded so later stages can
    # load the copied configuration and resolve the same inputs.
    originals = run.path / "originals"
    path_map: dict[str, str] = {}
    policy_copies: list[Path] = []
    for config_rel, src, dest in planned:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        path_map[config_rel] = str(dest)
        if config_rel in policy_rels:
            policy_copies.append(dest)
    shutil.copyfile(cfg.source_path, originals / "run-config.yaml")

    import uuid

    run_id = uuid.uuid4().hex[:12]
    run.update_manifest(
        lambda m: m.update(
            {
                "schema_version": 1,
                "run_id": run_id,
                "label": (cfg.raw.get("run") or {}).get("label") or target.name,
                "subject": cfg.subject,
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
                "runs_root": str(target.parent.resolve()),
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
        runs_root=str(target.parent.resolve()),
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
                + (
                    " This is a DESIGN-TIME run: the subject is a proposed "
                    "design, so the pipeline stops after the Scenario "
                    "Generator and no evaluation will be attempted."
                    if cfg.subject == "proposed"
                    else ""
                )
            ),
            material=material,
            summary={
                "subject": cfg.subject,
                "subject_note": report.get("subject_note"),
                "advisories": report.get("advisories", []),
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
            _stage_record(run, "conflict_review", state="resolved")
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
            # The stage status reflects the *effective* attempt: a failed
            # retry must not mark the stage failed when an earlier completed
            # attempt's output is still the effective mapper output.
            if result.status == FAILED:
                effective = run.manifest().get("flow", {}).get("mapper_output")
                if effective and effective.get("extraction"):
                    effective_attempt = effective["extraction"].split("/")[2]
                    effective_record = next(
                        (
                            a
                            for a in run.manifest()["stages"]["policy-mapper"]["attempts"]
                            if a.get("attempt_id") == effective_attempt
                        ),
                        None,
                    )
                    if effective_record and effective_record.get("status") in (
                        COMPLETED,
                        COMPLETED_WITH_GAPS,
                    ):

                        def keep_effective(manifest: dict) -> None:
                            stage_rec = manifest["stages"]["policy-mapper"]
                            stage_rec["status"] = effective_record["status"]
                            stage_rec["latest_attempt_status"] = FAILED

                        run.update_manifest(keep_effective)
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
            error_detail=result.error_detail,
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
        parse_filter_failures,
        parse_readiness_failure,
        write_profile_required_request,
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
            # Profile and facts are optional user inputs: without them the
            # generator's own Stage-1 inference runs.
            profile = (
                run.path / "originals" / "system" / cfg.resolved_path("profile_file").name
                if cfg.raw.get("system", {}).get("profile_file")
                else None
            )
            facts = (
                run.path / "originals" / "system" / cfg.resolved_path("qualification_facts_file").name
                if cfg.raw.get("system", {}).get("qualification_facts_file")
                else None
            )
            sssom = run.path / "originals" / "sssom" / cfg.sssom_path().name

            if profile is None:
                # The native projection preflight requires a reviewed
                # profile; with none supplied there is nothing to preflight —
                # the generator infers and its authoritative projection
                # defers unresolved conditions (omitted_compatibility).
                preflight_outcome = {
                    "skipped": "no capability profile supplied",
                    "note": "Stage-1 inference will produce an inferred_partial "
                    "profile; an inferred-only run can finish with zero scenarios",
                }
                atomic_write_json(attempt_dir / "projection-preflight.json", preflight_outcome)
            try:
                if profile is not None:
                    preflight_outcome = run_projection_preflight(
                        cfg,
                        attempt_dir,
                        use_case_file=use_case,
                        risk_extraction=extraction_path,
                        sssom=sssom,
                        profile=profile,
                        qualification_facts=facts if facts and facts.is_file() else None,
                        facts_template=attempt_dir / "facts-template.yaml",
                    )
                else:
                    preflight_outcome = json.loads(
                        (attempt_dir / "projection-preflight.json").read_text(encoding="utf-8")
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
                qualification_facts=facts if facts and facts.is_file() else None,
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

            # Resolve the run directory: newest child under runs/. A
            # non-zero exit is NOT itself failure (quarantined candidates
            # exit non-zero by design) — but no run directory at all means
            # the native CLI aborted, and its stderr carries the reason.
            try:
                scenario_run_dir = _latest_scenario_run(output_dir)
                manifest = read_run_manifest(scenario_run_dir)
                admitted, quarantined = resolve_admitted(scenario_run_dir)
            except (FileNotFoundError, RuntimeError) as exc:
                stderr_text = ""
                stderr_path = attempt_dir / "stderr.log"
                if stderr_path.is_file():
                    stderr_text = stderr_path.read_text(
                        encoding="utf-8", errors="replace"
                    )
                stderr_tail = "\n".join(stderr_text.splitlines()[-8:])
                from .health import extract_error_summary

                error_summary = extract_error_summary(stderr_text) if stderr_text else None
                detail = (
                    f"scenario generator exited with code {proc.returncode} "
                    "before producing a run directory"
                    + (f": {error_summary}" if error_summary else "")
                    if proc.returncode != 0
                    else str(exc)
                )

                # A projection-readiness abort without a reviewed profile is
                # not a generic failure: the operator must supply a profile
                # (the inferred-only profile cannot provide Stage-2 inventory
                # evidence). Present it as a durable review request with the
                # missing categories, not a bare 'failed'.
                missing_categories = parse_readiness_failure(stderr_text)
                if missing_categories and profile is None:
                    request_path = write_profile_required_request(
                        run, attempt_id, missing_categories
                    )
                    blockers = [
                        "projection readiness requires architecture evidence "
                        f"missing from the inferred profile: {', '.join(missing_categories)}",
                        "supply a reviewed capability profile (system.profile_file) "
                        "and start a new run; see reviews/profile-required.request.json",
                    ]
                    run.record_stage_outcome(
                        "scenario-generator",
                        attempt_id,
                        {
                            "status": NEEDS_REVIEW,
                            "error": detail,
                            "returncode": proc.returncode,
                            "missing_resource_categories": missing_categories,
                        },
                    )
                    _stage_record(run, "profile_required", state="pending")
                    return Outcome("scenarios", run_dir).finish(
                        NEEDS_REVIEW,
                        blockers=blockers,
                        review={
                            "kind": "profile-required",
                            "request": run.rel(request_path),
                            "missing_resource_categories": missing_categories,
                        },
                        error_detail=error_summary,
                        stderr_tail=stderr_tail[-1500:],
                        attempt=attempt_id,
                    )

                run.record_stage_outcome(
                    "scenario-generator",
                    attempt_id,
                    {"status": FAILED, "error": detail, "returncode": proc.returncode},
                )
                return Outcome("scenarios", run_dir).finish(
                    FAILED,
                    blockers=[detail],
                    error=detail,
                    error_detail=error_summary,
                    stderr_tail=stderr_tail[-1500:],
                    attempt=attempt_id,
                )

            handoff_dir = attempt_dir / "handoff"
            receipts = handoff_receipts(run, admitted, handoff_dir)
            # Scenarios without a sibling .feature are excluded from the
            # admitted count with an explicit gap — never silently dropped.
            missing_feature = [r for r in receipts if r.get("missing_feature")]
            inventory_summary = {
                "admitted": len(receipts) - len(missing_feature),
                "admitted_missing_feature": len(missing_feature),
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
            if len(receipts) == len(missing_feature):
                blockers = [
                    "zero admitted scenarios with a sibling .feature file; "
                    "an incomplete evaluation, not a successful end-to-end result"
                ]
                if missing_feature:
                    blockers[0] += (
                        f" ({len(missing_feature)} admitted scenario(s) lack the "
                        "adjacent .feature file the artifact loader reads)"
                    )
                return Outcome("scenarios", run_dir).finish(
                    BLOCKED,
                    blockers=blockers,
                    inventory_summary=inventory_summary,
                )
            _stage_record(
                run,
                "scenario_handoff",
                receipts=str((handoff_dir / "handoff-receipts.json").relative_to(run.path)),
                scenario_run_dir=run.rel(scenario_run_dir),
            )
            gaps = []
            if quarantined:
                gaps.append(
                    f"{len(quarantined)} quarantined candidates retained in the "
                    "native quarantine inventory"
                )
            for r in missing_feature:
                gaps.append(
                    f"{r['scenario_id']}: missing sibling .feature file — "
                    "excluded from handoff"
                )
            # Filter-call failures are quarantine-level (a seed's candidate
            # is dropped), not fatal — surface them distinctly in the outcome
            # instead of leaving them buried in stderr.
            stderr_path = attempt_dir / "stderr.log"
            if stderr_path.is_file():
                for seed in parse_filter_failures(
                    stderr_path.read_text(encoding="utf-8", errors="replace")
                ):
                    gaps.append(
                        f"{seed}: filter call failed (completion length exceeded) "
                        "— candidate quarantined, not fatal"
                    )
            return Outcome("scenarios", run_dir).finish(
                COMPLETED_WITH_GAPS if (quarantined or missing_feature) else COMPLETED,
                inventory_summary=inventory_summary,
                admitted=[r["scenario_id"] for r in receipts if not r.get("missing_feature")],
                handoff=run.rel(handoff_dir / "handoff-receipts.json"),
                gaps=gaps,
            )


def _preflight_unresolved(preflight_outcome: dict) -> list[dict]:
    """Extract unresolved fact conditions from the native preflight JSON.

    The native ProjectionPreflightOutcome emits ``readiness`` (with
    ``ready`` and ``missing_facts``) and ``fact_states`` whose ``status``
    is present|absent|unknown|stale|contradictory. Only ``present`` facts
    are resolved; anything else required by a selected pattern is a
    durable pending-review condition.
    """
    unresolved = []
    for item in preflight_outcome.get("fact_states", []) or []:
        if not isinstance(item, dict):
            continue
        if item.get("status") != "present":
            unresolved.append(item)
    readiness = preflight_outcome.get("readiness") or {}
    if readiness and not readiness.get("ready", True):
        # Record the native missing list too, if not already covered.
        missing = set(readiness.get("missing_facts", []) or [])
        seen = {
            str((item.get("fact") or {}).get("fact_id")) for item in unresolved
        }
        for fact_id in sorted(missing - seen):
            unresolved.append(
                {
                    "fact": {"fact_id": fact_id},
                    "status": "missing",
                    "source": "readiness.missing_facts",
                }
            )
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
        design_gate = _require_built_subject(run, "artifacts", run_dir)
        if design_gate is not None:
            return design_gate
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
            eligibility_pairs, handoff_exclusions = eligibility_for_batch(
                run, handoff_receipts
            )
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
            excluded = handoff_exclusions + [
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
                    scenario_paths.append(run.path / receipt["yaml"])

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
        design_gate = _require_built_subject(run, "replay-review", run_dir)
        if design_gate is not None:
            return design_gate
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
            [(e["entry_path"], "replay entry (exact evaluated input)") for e in entries]
            + [(e["meta_path"], "replay metadata (parents, schema derivations)")
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
        design_gate = _require_built_subject(run, "evaluate", run_dir)
        if design_gate is not None:
            return design_gate
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
            inconclusive = [r for r in results if r.outcome == "inconclusive"]
            if results and usable:
                # A usable result with inconclusive siblings is
                # completed_with_gaps, per the CLI contract.
                status = COMPLETED_WITH_GAPS if inconclusive else COMPLETED
            else:
                status = COMPLETED_WITH_GAPS if results else BLOCKED
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
# log (live progress for long stages)
# ---------------------------------------------------------------------------


@app.command()
def log(
    run_dir: Annotated[str, typer.Argument(help="Run directory")],
    stage: Annotated[
        str,
        typer.Option(
            help="Stage to tail (policy-mapper|map, scenario-generator|scenarios, "
            "artifact-generator|artifacts, garak|evaluate). Default: the most "
            "recently active attempt across stages."
        ),
    ] = "",
    lines: Annotated[int, typer.Option(help="Number of log lines to show")] = 30,
):
    """Tail a running (or finished) stage attempt's log — plain text.

    Convenience for humans and agents: while a long stage runs in the
    background, call this periodically and summarize the last few lines
    (chunk progress, model calls, tokens) instead of leaving the user in
    silence.
    """
    run = _load_run(run_dir)
    aliases = {
        "map": "policy-mapper",
        "scenarios": "scenario-generator",
        "artifacts": "artifact-generator",
        "evaluate": "garak",
    }
    stage_name = aliases.get(stage, stage) if stage else None
    stage_dirs = [d for d in (run.path / "stages").iterdir() if d.is_dir()]
    if stage_name:
        if stage_name not in [d.name for d in stage_dirs]:
            raise typer.BadParameter(f"no attempts recorded for stage {stage_name!r}")
        stage_dirs = [run.path / "stages" / stage_name]
    # Most recently modified attempt across the selected stage(s).
    attempts = [a for d in stage_dirs for a in d.iterdir() if a.is_dir()]
    if not attempts:
        print("[asago-runner log] no stage attempts recorded in this run yet")
        return typer.Exit(code=0)
    latest = max(attempts, key=lambda a: a.stat().st_mtime)
    sources = []
    stderr = latest / "stderr.log"
    if stderr.is_file():
        sources.append(stderr)
    # The scenario generator also writes a detailed pipeline log inside its
    # native run directory.
    for pipeline_log in sorted((latest / "runs").rglob("pipeline.log")):
        sources.append(pipeline_log)
    if not sources:
        print(f"[asago-runner log] no logs yet in {run.rel(latest)}")
        return typer.Exit(code=0)
    print(f"[asago-runner log] {run.rel(latest)}")
    for source in sources:
        text = source.read_text(encoding="utf-8", errors="replace").splitlines()
        tail = text[-lines:]
        if tail:
            print(f"--- {source.name} ({len(text)} lines) ---")
            for line in tail:
                print(line[:240])
    return typer.Exit(code=0)


# ---------------------------------------------------------------------------
# watch (deterministic stage health for progress updates)
# ---------------------------------------------------------------------------


@app.command()
def watch(
    run_dir: Annotated[str, typer.Argument(help="Run directory")],
    stage: Annotated[
        str,
        typer.Option(
            help="Stage to inspect (policy-mapper|map, scenario-generator|"
            "scenarios, artifact-generator|artifacts, garak|evaluate). "
            "Default: the most recently modified attempt.",
        ),
    ] = "",
    stall_seconds: Annotated[
        int,
        typer.Option(help="Seconds without log activity before reporting 'stalled'"),
    ] = 300,
    json_only: Annotated[
        bool, typer.Option("--json", help="Print only the final JSON line")
    ] = False,
    follow: Annotated[
        bool,
        typer.Option(
            "--follow",
            help="Keep polling and print a line whenever health or the last "
            "milestone changes; exit when the stage reaches a terminal state.",
        ),
    ] = False,
    interval: Annotated[
        int, typer.Option(help="Seconds between polls with --follow")
    ] = 30,
    timeout_seconds: Annotated[
        int,
        typer.Option(
            "--timeout", help="Give up following after this many seconds"
        ),
    ] = 3600,
):
    """Classify a running (or finished) stage's health deterministically.

    Prints a one-line human summary plus a machine-readable JSON line:
    health (running/retrying/stalled/failed/done), elapsed time, log
    silence, retry and error counts, the last milestone and the last error.

    With --follow it prints a line on every change and exits when the stage
    finishes — so a background watcher reports failures on its own. Relay
    every change immediately (especially retrying/stalled/failed); never
    wait for the user to ask.
    """
    import time

    from .health import render_health, summarize_attempt

    run = _load_run(run_dir)

    if not follow:
        summary = summarize_attempt(run, stage or None, stall_seconds=stall_seconds)
        if not json_only:
            print(render_health(summary))
        outcome = Outcome("watch", run_dir)
        return outcome.finish(COMPLETED, **summary)

    terminal = {"failed", "blocked", "needs_review", "done", "stopped"}
    start = time.monotonic()
    last_key = None
    last_printed = 0.0
    summary: dict = {}
    while True:
        summary = summarize_attempt(run, stage or None, stall_seconds=stall_seconds)
        key = (
            summary.get("health"),
            summary.get("last_milestone"),
            summary.get("retry_count"),
            summary.get("error_count"),
        )
        now = time.monotonic()
        # Print on a change *and* as a heartbeat every interval, so a long
        # single model call never looks like silence to a watcher.
        if key != last_key or now - last_printed >= max(5, interval):
            print(render_health(summary), flush=True)
            last_key = key
            last_printed = now
        if summary.get("health") in terminal:
            break
        if time.monotonic() - start >= timeout_seconds:
            print(
                f"[asago-runner] watch: still {summary.get('health')} after "
                f"{timeout_seconds}s; stopping the watcher (the stage keeps running)",
                flush=True,
            )
            break
        time.sleep(max(5, interval))
    outcome = Outcome("watch", run_dir)
    if summary.get("health") == "needs_review":
        status = NEEDS_REVIEW
    elif summary.get("health") in ("failed", "blocked", "stopped"):
        status = FAILED
    else:
        status = COMPLETED
    return outcome.finish(status, **summary)


# ---------------------------------------------------------------------------
# report / verify-run / status / respond
# ---------------------------------------------------------------------------


@app.command()
def report(
    run_dir: Annotated[str, typer.Argument(help="Run directory")],
    conversation: Annotated[
        str | None,
        typer.Option(
            "--conversation",
            help=(
                "Optional transcript of the session that ran the skill "
                "(Markdown or text). Defaults to reports/conversation.md in "
                "the run when present."
            ),
        ),
    ] = None,
):
    """Derive summary.json and render the offline HTML run report."""
    from .hashing import sha256_file
    from .reporting import build_summary, render_html

    run = _load_run(run_dir)
    with run.locked(f"report pid={__import__('os').getpid()}"):
        summary = build_summary(run)
        transcript = None
        source: Path | None = None
        if conversation:
            candidate = Path(conversation).expanduser()
            if not candidate.is_absolute():
                candidate = run.path / candidate
            resolved = candidate.resolve()
            run_root = run.path.resolve()
            try:
                resolved.relative_to(run_root)
            except ValueError:
                return Outcome("report", run_dir).finish(
                    FAILED,
                    error=(
                        "conversation transcript must be inside the run directory "
                        f"({run_root}); copy it there first (for example "
                        "reports/conversation.md). Reading arbitrary paths would "
                        "embed unrelated files in the report."
                    ),
                )
            if not resolved.is_file():
                return Outcome("report", run_dir).finish(
                    FAILED,
                    error=f"conversation transcript not found: {resolved}",
                )
            source = resolved
        else:
            default = (run.path / "reports" / "conversation.md").resolve()
            try:
                default.relative_to(run.path.resolve())
            except ValueError:
                default = None
            if default is not None and default.is_file():
                source = default
        if source is not None:
            transcript = source.read_text(encoding="utf-8", errors="replace")
            summary["conversation"] = {
                "source": run.rel(source),
                "sha256": sha256_file(source),
            }
        html_path = render_html(run, summary, transcript)
        run.rebuild_inventory()
        return Outcome("report", run_dir).finish(
            COMPLETED,
            summary=run.rel(run.path / "reports" / "summary.json"),
            html=run.rel(html_path),
            conversation_included=bool(transcript),
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
    """Print the run's current state: a progress checklist plus machine-readable JSON."""
    from .reporting import derive_progress, render_progress_checklist

    run = _load_run(run_dir)
    manifest = run.manifest()
    progress = derive_progress(manifest, run.path)
    # Human-readable checklist first; the final stdout line stays the JSON
    # contract. Agents should quote this block when narrating progress.
    print(render_progress_checklist(progress, manifest.get("run_id")))
    return Outcome("status", run_dir).finish(
        COMPLETED,
        run_id=manifest.get("run_id"),
        progress=progress,
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
        # A non-resolving decision (e.g. a rejection) is still a real
        # answer: record it in the journal with its visible notes, then
        # keep the gate closed.
        if response.get("decision"):
            run.append_decision(
                {
                    "category": request.kind,
                    "actor": {
                        "label": response.get("actor", "user"),
                        "identity_source": "review-file",
                    },
                    "question": request.question,
                    "evidence": request.material,
                    "response": response.get("decision"),
                    "visible_notes": response.get("visible_notes", ""),
                    "clarifications": response.get("clarifications", []),
                    "resolution": "gate remains closed (non-resolving decision)",
                    "scope": [entry["path"] for entry in request.material],
                    "state": "rejected",
                }
            )
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
