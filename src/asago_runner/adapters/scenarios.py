"""Scenario Generator stage adapter.

Runs the native taxonomy/risk workflow through its CLI:

1. a model-free ``projection-preflight`` on *this run's* real mapper output
   (not saved extraction) with the reviewed profile, qualification facts and
   the explicit, hashed SSSOM mapping — missing/unknown/contradictory facts
   return a durable pending-review request;
2. ``generate`` with the recorded bounded generation options (the native
   default is exhaustive).

Admitted outputs are resolved through the native finalization inventory and
hash contract — never by globbing a directory or trusting exit codes. Risk
selection (``scope.risk_ids``) is an explicit, recorded input adaptation: a
filtered copy of the mapper output is derived with provenance, and the
original is retained untouched.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..config import RunConfig
from ..evidence import RunDir, Stopwatch, atomic_write_json
from ..hashing import sha256_file
from ..proc import ProcResult, quote_command, run_subprocess

SCENARIO_CLI = "asago-scenario-generator"


@dataclass
class ScenarioOutcome:
    status: str
    attempt_dir: str
    run_dir: Path | None = None
    preflight: dict | None = None
    inventory: dict | None = None
    admitted: list[dict] = field(default_factory=list)
    quarantined: list[dict] = field(default_factory=list)
    selection: dict | None = None
    command: str = ""
    proc: ProcResult | None = None
    blockers: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    review: dict | None = None


def filter_risk_extraction(
    run: RunDir, extraction_path: Path, risk_ids: list[str]
) -> tuple[Path, dict]:
    """Explicit input adaptation: keep only selected risk IDs.

    The original mapper output is preserved; the filtered copy records what
    was dropped. Only ibm-risk-atlas risks are passed (the native loader
    filters to that taxonomy; other taxonomies were already accounted for at
    the mapper stage).
    """
    data = json.loads(extraction_path.read_text(encoding="utf-8"))
    risks = data.get("risks", [])
    selected = [r for r in risks if r.get("risk_id") in risk_ids]
    dropped = [
        {"risk_id": r.get("risk_id"), "taxonomy": r.get("taxonomy")}
        for r in risks
        if r.get("risk_id") not in risk_ids
    ]
    data["risks"] = selected
    out_dir = run.path / "derived"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "risk-extraction-selected.json"
    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    record = {
        "adaptation": "risk-selection",
        "source": str(extraction_path),
        "source_sha256": sha256_file(extraction_path),
        "selected_risk_ids": risk_ids,
        "kept": len(selected),
        "dropped": dropped,
        "output": run.rel(out_path),
        "output_sha256": sha256_file(out_path),
        "note": (
            "reviewed scope selection; the mapper output itself is retained "
            "unmodified alongside this derived effective input"
        ),
    }
    atomic_write_json(out_dir / "risk-selection.json", record)
    return out_path, record


def run_projection_preflight(
    config: RunConfig,
    attempt_dir: Path,
    *,
    use_case_file: Path,
    risk_extraction: Path,
    sssom: Path,
    profile: Path,
    qualification_facts: Path | None,
    facts_template: Path,
) -> dict:
    """Run the native model-free projection preflight; returns its JSON."""
    from ..paths import component_cli

    argv = [
        component_cli(SCENARIO_CLI),
        "projection-preflight",
        "--use-case",
        f"@{use_case_file}",
        "--risk-extraction",
        str(risk_extraction),
        "--sssom",
        str(sssom),
        "--profile",
        str(profile),
    ]
    if qualification_facts is not None:
        argv += ["--qualification-facts", str(qualification_facts)]
    argv += ["--facts-template", str(facts_template)]
    proc = run_subprocess(
        argv,
        cwd=attempt_dir,
        deadline_seconds=600,
        env_extra={},
        stdout_path=attempt_dir / "preflight-stdout.json",
        stderr_path=attempt_dir / "preflight-stderr.log",
    )
    if proc.returncode != 0 or proc.timed_out:
        raise RuntimeError(
            f"projection-preflight failed (rc={proc.returncode}, "
            f"timed_out={proc.timed_out}); see {attempt_dir / 'preflight-stderr.log'}"
        )
    return json.loads((attempt_dir / "preflight-stdout.json").read_text(encoding="utf-8"))


def run_generate(
    config: RunConfig,
    attempt_dir: Path,
    *,
    use_case_file: Path,
    risk_extraction: Path,
    sssom: Path,
    profile: Path,
    qualification_facts: Path | None,
    output_dir: Path,
) -> tuple[ProcResult, str]:
    """Run the native generate pipeline with bounded, recorded options."""
    conn = config.connections["scenario_llm"].resolve()
    from ..paths import component_cli

    argv = [
        component_cli(SCENARIO_CLI),
        "generate",
        "--use-case",
        f"@{use_case_file}",
        "--risk-extraction",
        str(risk_extraction),
        "--sssom",
        str(sssom),
        "--output-dir",
        str(output_dir),
        "--profile",
        str(profile),
        "--generation-mode",
        config.generation_mode,
    ]
    if config.max_scenarios_per_pattern is not None:
        argv += ["--max-scenarios-per-pattern", str(config.max_scenarios_per_pattern)]
    if qualification_facts is not None:
        argv += ["--qualification-facts", str(qualification_facts)]
    env: dict[str, str] = {}
    if conn.get("base_url"):
        env["ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL"] = str(conn["base_url"])
    if conn.get("model"):
        env["ASAGO_SCENARIO_GENERATOR_MODEL_NAME"] = str(conn["model"])
    if conn.get("api_key"):
        env["ASAGO_SCENARIO_GENERATOR_API_KEY"] = str(conn["api_key"])
    options = config.raw.get("options") or {}
    if options.get("scenario_temperature") is not None:
        env["ASAGO_SCENARIO_GENERATOR_TEMPERATURE"] = str(options["scenario_temperature"])
    if options.get("scenario_max_completion_tokens"):
        env["ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS"] = str(
            options["scenario_max_completion_tokens"]
        )
    env["ASAGO_SCENARIO_GENERATOR_TIMEOUT"] = str(min(config.stage_deadline_seconds, 300))
    proc = run_subprocess(
        argv,
        cwd=attempt_dir,
        deadline_seconds=config.stage_deadline_seconds,
        env_extra=env,
        stdout_path=attempt_dir / "stdout.log",
        stderr_path=attempt_dir / "stderr.log",
        dispatch_record_path=attempt_dir / "dispatch.json",
    )
    # Record the effective non-secret model identity for this attempt.
    from ..config import _host_of

    atomic_write_json(
        attempt_dir / "model-identity.json",
        {
            "role": "scenario_llm",
            "model": conn.get("model"),
            "base_url_host": _host_of(conn.get("base_url")),
            "temperature": (config.raw.get("options") or {}).get("scenario_temperature"),
            "note": "requested model; returned model IDs are unknown unless captured",
        },
    )
    return proc, quote_command(argv)


def read_run_manifest(scenario_run_dir: Path) -> dict:
    path = scenario_run_dir / "run-manifest.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"run-manifest.yaml missing in {scenario_run_dir}")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def read_finalization_inventory(scenario_run_dir: Path) -> dict:
    path = scenario_run_dir / "finalization-inventory.json"
    if not path.is_file():
        raise FileNotFoundError(
            f"finalization-inventory.json missing in {scenario_run_dir}"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_admitted(scenario_run_dir: Path) -> tuple[list[dict], list[dict]]:
    """Resolve admitted scenarios through the native inventory/hash contract.

    Returns (admitted, quarantined) receipt lists with verified hashes and
    absolute paths. Quarantine bundles are retained for visibility.
    """
    inventory = read_finalization_inventory(scenario_run_dir)
    admitted: list[dict] = []
    quarantined: list[dict] = []
    for receipt in inventory.get("admitted_inventory", []):
        if receipt.get("role") not in ("scenario_yaml", "scenario_feature"):
            continue
        path = scenario_run_dir / receipt["path"]
        entry = {
            "candidate_id": receipt.get("candidate_id"),
            "role": receipt.get("role"),
            "scenario_id": receipt.get("scenario_id"),
            "path": str(path),
            "recorded_sha256": receipt.get("sha256"),
            "actual_sha256": sha256_file(path) if path.is_file() else None,
        }
        if entry["actual_sha256"] != entry["recorded_sha256"]:
            raise RuntimeError(
                f"admission receipt hash mismatch for {receipt['path']}: "
                "the native inventory contract failed"
            )
        admitted.append(entry)
    for receipt in inventory.get("quarantine_inventory", []):
        path = scenario_run_dir / receipt["path"]
        quarantined.append(
            {
                "candidate_id": receipt.get("candidate_id"),
                "role": receipt.get("role"),
                "path": str(path),
                "recorded_sha256": receipt.get("sha256"),
                "exists": path.is_file(),
            }
        )
    return admitted, quarantined


def handoff_receipts(
    run: RunDir, admitted: list[dict], handoff_dir: Path
) -> list[dict]:
    """Copy admitted YAML + adjacent .feature files for artifact generation.

    Receipt hashes are rechecked after the copy (the artifact loader
    implicitly reads the sibling feature file, so it is part of the effective
    input). Canonical scenario files are never modified.
    """
    handoff_dir.mkdir(parents=True, exist_ok=True)
    receipts = []
    by_scenario: dict[str, dict] = {}
    for entry in admitted:
        if entry["role"] != "scenario_yaml":
            continue
        by_scenario.setdefault(entry["scenario_id"], {})[
            "yaml"
        ] = entry
    for entry in admitted:
        if entry["role"] == "scenario_feature":
            sid = entry.get("scenario_id")
            if sid in by_scenario:
                by_scenario[sid]["feature"] = entry
    for scenario_id, pair in sorted(by_scenario.items()):
        yaml_entry = pair["yaml"]
        src_yaml = Path(yaml_entry["path"])
        dst_yaml = handoff_dir / src_yaml.name
        shutil.copyfile(src_yaml, dst_yaml)
        record = {
            "scenario_id": scenario_id,
            "yaml": str(dst_yaml),
            "yaml_sha256_after_copy": sha256_file(dst_yaml),
            "canonical_yaml_sha256": yaml_entry["recorded_sha256"],
        }
        feature_entry = pair.get("feature")
        if feature_entry:
            src_feature = Path(feature_entry["path"])
            dst_feature = handoff_dir / src_feature.name
            shutil.copyfile(src_feature, dst_feature)
            record["feature"] = str(dst_feature)
            record["feature_sha256_after_copy"] = sha256_file(dst_feature)
            record["canonical_feature_sha256"] = feature_entry["recorded_sha256"]
        else:
            record["feature"] = None
            record["missing_feature"] = (
                "no adjacent .feature file in the admitted inventory; the "
                "artifact loader reads it implicitly, so this scenario is "
                "excluded from handoff"
            )
        receipts.append(record)
    atomic_write_json(handoff_dir / "handoff-receipts.json", receipts)
    return receipts
