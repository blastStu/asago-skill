"""Artifact Generator stage adapter.

For each admitted scenario:
1. derive a model-free transport eligibility record *before* any artifact
   model call (see ``replay.derive_transport``); ineligible scenarios are
   excluded with recorded reasons — never silently defaulted;
2. where a provenance-backed zone-suffix adaptation is required, write an
   adapted scenario YAML (canonical files preserved, transformation recorded);
3. invoke the real Artifact Generator CLI with explicit scenario paths (never
   its example defaults) into a dedicated output directory (its manifest is
   overwritten per invocation), with a managed provider selection so stray
   keys or ambient ``.env`` files cannot reroute the model;
4. after generation, assert the artifact's surface, attack role/index and
   tool pairing agree with the runner's expected transport; build and persist
   the immutable replay entries for review.

Coverage status (full/partial/skip) is kept separate from structural
validation (ok/errors). ``skip`` may coexist with ``ok=true`` and remains
skipped. ``--force`` is never used.
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
from ..replay import Eligibility, build_replay_entry, derive_transport

ARTIFACT_CLI = "asago-artifact-generator"


@dataclass
class ArtifactStageResult:
    status: str
    attempt_dir: str
    command: str = ""
    proc: ProcResult | None = None
    manifest: list[dict] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)
    replay_entries: list[dict] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)


def load_scenario_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def eligibility_for_batch(
    handoff_receipts: list[dict],
) -> list[tuple[dict, Eligibility]]:
    """Derive eligibility for every handed-off scenario (model-free)."""
    results = []
    for receipt in handoff_receipts:
        if not receipt.get("yaml") or receipt.get("missing_feature"):
            continue
        scenario = load_scenario_yaml(Path(receipt["yaml"]))
        eligibility = derive_transport(scenario)
        results.append((receipt, eligibility))
    return results


def adapted_scenario(
    run: RunDir, receipt: dict, eligibility: Eligibility, adapted_dir: Path
) -> Path:
    """Write the adapted scenario YAML when a zone-suffix adaptation applies.

    The canonical admitted YAML is preserved untouched; the adapted copy is a
    separately recorded derivation with hashes of both parents.
    """
    adapted_dir.mkdir(parents=True, exist_ok=True)
    src = Path(receipt["yaml"])
    scenario = load_scenario_yaml(src)
    scenario["narrative"]["entry_point"] = eligibility.adaptation["new_entry_point"]
    dst = adapted_dir / src.name
    dst.write_text(yaml.safe_dump(scenario, sort_keys=False), encoding="utf-8")
    if receipt.get("feature"):
        shutil.copyfile(receipt["feature"], adapted_dir / Path(receipt["feature"]).name)
    atomic_write_json(
        adapted_dir / f"{src.stem}.adaptation.json",
        {
            "kind": "provenance-backed-surface-adaptation",
            "canonical_yaml": str(src),
            "canonical_yaml_sha256": sha256_file(src),
            "adapted_yaml": str(dst),
            "adapted_yaml_sha256": sha256_file(dst),
            "adaptation": eligibility.adaptation,
            "eligibility_reason": eligibility.reason,
            "note": (
                "input adaptation only; no upstream source modified; the "
                "canonical admitted scenario is retained alongside"
            ),
        },
    )
    return dst


def run_artifact_generator(
    config: RunConfig,
    attempt_dir: Path,
    scenario_paths: list[Path],
    output_dir: Path,
) -> tuple[ProcResult, str]:
    """Invoke the real Artifact Generator CLI for the selected scenarios."""
    conn = config.connections["artifact_llm"].resolve()
    from ..paths import component_cli

    argv = [
        component_cli(ARTIFACT_CLI),
        "generate",
        *[str(p) for p in scenario_paths],
        "--output-dir",
        str(output_dir),
    ]
    env: dict[str, str] = {
        # Explicit provider selection: no auto-detection from stray keys.
        "REDTEAM_PROVIDER": "openai",
        "REDTEAM_MODEL": str(conn["model"]),
        "OPENAI_BASE_URL": str(conn["base_url"]),
    }
    if conn.get("api_key"):
        env["OPENAI_API_KEY"] = str(conn["api_key"])
    options = config.raw.get("options") or {}
    if options.get("artifact_max_tokens"):
        env["REDTEAM_MAX_TOKENS"] = str(options["artifact_max_tokens"])
    if options.get("artifact_max_completion_tokens"):
        env["REDTEAM_MAX_COMPLETION_TOKENS"] = str(
            options["artifact_max_completion_tokens"]
        )
    proc = run_subprocess(
        argv,
        cwd=attempt_dir,  # clean working directory: no ambient .env
        deadline_seconds=config.stage_deadline_seconds,
        env_extra=env,  # allowlist: unrelated provider keys cannot leak in
        stdout_path=attempt_dir / "stdout.log",
        stderr_path=attempt_dir / "stderr.log",
        dispatch_record_path=attempt_dir / "dispatch.json",
    )
    # Record the effective non-secret model identity for this attempt.
    from ..config import _host_of

    atomic_write_json(
        attempt_dir / "model-identity.json",
        {
            "role": "artifact_llm",
            "model": conn.get("model"),
            "base_url_host": _host_of(conn.get("base_url")),
            "provider": "openai (explicit REDTEAM_PROVIDER; no auto-detection)",
            "note": "requested model; returned model IDs are unknown unless captured",
        },
    )
    return proc, quote_command(argv)


def process_manifest(
    attempt_dir: Path,
    output_dir: Path,
    eligibility_pairs: list[tuple[dict, Eligibility]],
    receipts_by_yaml: dict[str, dict],
) -> tuple[list[dict], list[str], list[str]]:
    """Post-process the artifact manifest into executable candidates.

    Returns (candidates, gaps, blockers). A candidate is executable only with
    successful required validation, usable conversation turns and a supported
    transport that matches the runner's expectation.
    """
    manifest_path = output_dir / "manifest.json"
    if not manifest_path.is_file():
        return [], [], [f"artifact generator wrote no manifest at {manifest_path}"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    candidates: list[dict] = []
    gaps: list[str] = []
    blockers: list[str] = []

    eligibility_by_scenario = {
        eligibility.scenario_id: eligibility for _, eligibility in eligibility_pairs
    }
    for entry in manifest:
        sid = entry.get("scenario_id")
        gate = entry.get("gate_result")
        ok = bool(entry.get("ok"))
        if entry.get("error"):
            gaps.append(f"{sid}: processing error: {entry['error']}")
            continue
        if gate == "skip":
            # skip may coexist with ok=true; it remains skipped.
            gaps.append(
                f"{sid}: coverage skip ({entry.get('gate_reason')}); ok={ok}; "
                "skipped regardless of validation status"
            )
            continue
        if not ok:
            gaps.append(
                f"{sid}: structural validation failed; never admitted with --force"
            )
            continue
        artifact_path = Path(entry["artifact_path"]) if entry.get("artifact_path") else None
        if artifact_path is None or not artifact_path.is_file():
            gaps.append(f"{sid}: no artifact file written")
            continue
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        eligibility = eligibility_by_scenario.get(sid)
        if eligibility is None:
            gaps.append(f"{sid}: no eligibility record; excluded")
            continue
        validation_path = output_dir / sid / "validation.json"
        candidates.append(
            {
                "scenario_id": sid,
                "gate": gate,
                "gate_reason": entry.get("gate_reason"),
                "ok": ok,
                "artifact_path": str(artifact_path),
                "artifact_sha256": sha256_file(artifact_path),
                "validation_path": str(validation_path),
                "validation": json.loads(validation_path.read_text(encoding="utf-8"))
                if validation_path.is_file()
                else None,
                "eligibility": eligibility,
                "receipt": receipts_by_yaml.get(sid),
                "artifact": artifact,
            }
        )
        if gate == "partial":
            gaps.append(
                f"{sid}: partial coverage ({entry.get('gate_reason')}); the "
                "omitted behavior must be visible in the reviewed test plan"
            )
    return candidates, gaps, blockers


def write_replay_entries(
    run: RunDir,
    attempt_dir: Path,
    candidates: list[dict],
    config: RunConfig,
) -> tuple[list[dict], list[str]]:
    """Build and persist immutable replay entries for the review boundary."""
    entries_dir = attempt_dir / "replay-entries"
    entries_dir.mkdir(parents=True, exist_ok=True)
    reviewed_schema = None
    if config.tools_schema_file:
        schema_path = Path(config.tools_schema_file)
        reviewed_schema = {
            "tools": json.loads(schema_path.read_text(encoding="utf-8")).get("tools", []),
            "path": str(schema_path),
            "sha256": sha256_file(schema_path),
        }
    target_conn = config.connections["target"].sanitized()
    judge_conn = config.connections["judge"].sanitized()
    config_identity = {
        "target": target_conn,
        "judge": judge_conn,
        "shared_model_roles": config.shared_model_roles(),
        "detector": "injection_judge.InjectionJudge",
        "confidence_cutoff": 70,
        "generations": config.target_samples_per_artifact,
    }

    written: list[dict] = []
    gaps: list[str] = []
    for candidate in candidates:
        receipt = candidate.get("receipt") or {}
        scenario_paths = {
            "scenario_yaml": receipt.get("yaml"),
            "scenario_feature": receipt.get("feature"),
        }
        entry, errors = build_replay_entry(
            candidate["artifact"],
            eligibility=candidate["eligibility"],
            scenario_paths=scenario_paths,
            artifact_path=candidate["artifact_path"],
            reviewed_schema=reviewed_schema,
            config_identity=config_identity,
        )
        if errors:
            gaps.append(
                f"{candidate['scenario_id']}: replay entry rejected: " + "; ".join(errors)
            )
            continue
        sid = candidate["scenario_id"]
        entry_path = entries_dir / f"{sid}.replay-entry.json"
        payload = dict(entry)
        payload.pop("_meta", None)
        entry_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        meta_path = entries_dir / f"{sid}.replay-meta.json"
        atomic_write_json(meta_path, entry["_meta"])
        written.append(
            {
                "scenario_id": sid,
                "entry_path": str(entry_path),
                "entry_sha256": sha256_file(entry_path),
                "meta_path": str(meta_path),
                "meta_sha256": sha256_file(meta_path),
                "surface": candidate["eligibility"].surface,
                "parent_artifact_sha256": candidate["artifact_sha256"],
            }
        )
    return written, gaps
