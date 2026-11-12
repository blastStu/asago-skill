"""Policy Mapper stage adapter.

Invokes the real mapper CLI (not the Python API) as an isolated subprocess so
its preprocessing (taxonomy exclusions, description overrides) and
postprocessing (mitigation enrichment, reporting) stay upstream. The Nexus
cache path is passed through the mapper's supported ``--nexus-base-dir``
setting. After the run, the adapter performs accounting the native payload
does not provide on its own: per-document representation, per-taxonomy
counts, downstream-supported risk counts and the agentic-filter state.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..config import RunConfig
from ..evidence import RunDir, Stopwatch, atomic_write_json
from ..proc import ProcResult, quote_command, run_subprocess

MAPPER_CLI = "asago-policy-mapper"


@dataclass
class MapperOutcome:
    status: str
    attempt_dir: str
    command: str
    proc: ProcResult | None = None
    extraction: dict | None = None
    accounting: dict = field(default_factory=dict)
    blockers: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    review: dict | None = None


def build_mapper_argv(
    config: RunConfig,
    policy_paths: list[Path],
    output_dir: Path,
    nexus_base_dir: Path,
    *,
    no_llm: bool = False,
) -> tuple[list[str], dict[str, str]]:
    """Build the mapper CLI argument array and its environment additions.

    The API key travels via environment (never argv, which ps would expose).
    In ``no_llm`` mode the LLM endpoint flags are omitted entirely: the CLI
    only requires them when an LLM stage is enabled.
    """
    conn = config.connections["mapper_llm"].resolve()
    from ..paths import component_cli

    argv = [
        component_cli(MAPPER_CLI),
        "extract",
        *[str(p) for p in policy_paths],
        "--output",
        str(output_dir),
        "--nexus-base-dir",
        str(nexus_base_dir),
        "--output-format",
        "json",
    ]
    if not no_llm:
        argv += [
            "--base-url",
            str(conn["base_url"]),
            "--model",
            str(conn["model"]),
        ]
    if config.ocr:
        argv.append("--ocr")
    options = config.raw.get("options") or {}
    if options.get("mapper_output_token_parameter"):
        argv += [
            "--output-token-parameter",
            str(options["mapper_output_token_parameter"]),
        ]
    if options.get("mapper_temperature") is not None:
        argv += ["--temperature", str(options["mapper_temperature"])]
    env: dict[str, str] = {}
    if not no_llm and conn.get("api_key"):
        env["POLICY_MAPPER_API_KEY"] = str(conn["api_key"])
    # Retrieval models: local defaults unless the configuration overrides them.
    retrieval = config.raw.get("retrieval") or {}
    if retrieval.get("bi_encoder_model"):
        argv += ["--bi-encoder-model", str(retrieval["bi_encoder_model"])]
    if retrieval.get("cross_encoder_model"):
        argv += ["--cross-encoder-model", str(retrieval["cross_encoder_model"])]
    if retrieval.get("query_instruction") is not None:
        argv += ["--query-instruction", str(retrieval["query_instruction"])]
    if retrieval.get("no_cross_encoder"):
        argv.append("--no-cross-encoder")
    return argv, env


def run_mapper(
    run: RunDir,
    config: RunConfig,
    attempt_dir: Path,
    policy_paths: list[Path],
    nexus_base_dir: Path,
    *,
    no_llm: bool = False,
) -> MapperOutcome:
    """Run one mapper attempt. ``no_llm`` selects the model-free IR-only mode.

    The full no-LLM configuration must disable query generation, judging,
    grounding, causal synthesis AND sibling expansion (expansion grounding is
    itself an LLM call; the CLI's needs_llm condition treats it so).
    """
    argv, env = build_mapper_argv(
        config, policy_paths, attempt_dir, nexus_base_dir, no_llm=no_llm
    )
    if no_llm:
        argv += [
            "--no-query-gen",
            "--no-judge",
            "--no-grounding",
            "--no-causal-synthesis",
            "--no-expand-siblings",
        ]

    watch = Stopwatch()
    proc = run_subprocess(
        argv,
        cwd=attempt_dir,
        deadline_seconds=config.stage_deadline_seconds,
        env_extra=env,
        stdout_path=attempt_dir / "stdout.log",
        stderr_path=attempt_dir / "stderr.log",
        dispatch_record_path=attempt_dir / "dispatch.json",
    )
    outcome = MapperOutcome(
        status="failed",
        attempt_dir=str(attempt_dir),
        command=quote_command(argv),
        proc=proc,
    )
    atomic_write_json(
        attempt_dir / "attempt.json",
        {
            "component": "{cli_placeholder}",
            "component_commit": _component_commit(),
            "command": outcome.command,
            "argv": argv,
            "timing": watch.lap(),
            "returncode": proc.returncode,
            "timed_out": proc.timed_out,
            "termination_reason": proc.termination_reason,
            "env_names": proc.env_names,
            "no_llm_mode": no_llm,
        },
    )

    extraction_path = attempt_dir / "risk-extraction.json"
    if proc.timed_out:
        outcome.blockers.append(
            f"mapper exceeded the stage deadline ({config.stage_deadline_seconds}s); "
            "partial files retained; note that killing the local process does not "
            "cancel requests already accepted by the endpoint"
        )
        return outcome
    if proc.returncode != 0:
        outcome.blockers.append(
            f"mapper exited with code {proc.returncode}; see stderr.log"
        )
        return outcome
    if not extraction_path.is_file():
        outcome.blockers.append("mapper reported success but wrote no risk-extraction.json")
        return outcome

    extraction = json.loads(extraction_path.read_text(encoding="utf-8"))
    outcome.extraction = extraction
    outcome.accounting = account_extraction(extraction, policy_paths, attempt_dir)
    atomic_write_json(attempt_dir / "accounting.json", outcome.accounting)

    gaps = outcome.accounting["gaps"]
    blockers = outcome.accounting["blockers"]
    if blockers:
        outcome.status = "blocked"
        outcome.blockers.extend(blockers)
    elif gaps:
        outcome.status = "completed_with_gaps"
        outcome.gaps.extend(gaps)
    else:
        outcome.status = "completed"
    return outcome


def _component_commit() -> str:
    import importlib.metadata as im

    try:
        info = json.loads(im.distribution("asago-policy-mapper").read_text("direct_url.json"))
        return info.get("vcs_info", {}).get("commit_id", "unknown")
    except Exception:
        return "unknown"


# Downstream-supported taxonomy: the Scenario Generator's risk loader filters
# to ibm-risk-atlas. Anything else is recorded as unsupported downstream.
DOWNSTREAM_TAXONOMY = "ibm-risk-atlas"


def account_extraction(
    extraction: dict, policy_paths: list[Path], attempt_dir: Path
) -> dict:
    """Runner-owned accounting over the native extraction payload.

    Keeps parsed/no-match distinct from empty, filtered, excluded and unknown;
    inventories all returned taxonomies; surfaces the agentic-filter state.
    """
    risks = extraction.get("risks", [])
    source_documents = extraction.get("source_documents", []) or []
    supplied = [str(p) for p in policy_paths]

    per_taxonomy: dict[str, int] = {}
    for risk in risks:
        tax = risk.get("taxonomy", "unknown")
        per_taxonomy[tax] = per_taxonomy.get(tax, 0) + 1

    downstream_supported = [r for r in risks if r.get("taxonomy") == DOWNSTREAM_TAXONOMY]

    # Document representation: source_documents lists every supplied path,
    # even on the empty-result path; it does not prove successful parsing.
    # Pair it with the intake receipts recorded earlier in the run.
    receipts_path = attempt_dir.parents[2] / "derived" / "intake-receipts.json"
    receipts = json.loads(receipts_path.read_text(encoding="utf-8")) if receipts_path.is_file() else []
    represented = [d for d in source_documents if d in supplied]

    # Agentic filter: the pipeline removes agentic candidates before retrieval
    # when no document uses agent terminology. Derive from the native
    # retrieval_stats where available (candidate counts), cross-checked with
    # a clearly labelled prediction from the preserved parsed text.
    agentic_removed = None
    stats = extraction.get("retrieval_stats", {}) or {}
    stderr_text = ""
    stderr_path = attempt_dir / "stderr.log"
    if stderr_path.is_file():
        stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    if re.search(r"no agent|agent terminology|agentic risks removed", stderr_text, re.I):
        agentic_removed = True
    elif stats.get("candidates_before_agentic_filter") is not None:
        agentic_removed = stats["candidates_before_agentic_filter"] != stats.get(
            "total_candidates"
        )

    llm_calls = extraction.get("llm_calls", []) or []
    gaps: list[str] = []
    blockers: list[str] = []

    if not represented and supplied:
        blockers.append(
            "no supplied document is represented in the extraction result; "
            "check intake receipts for parse failures"
        )
    failed_receipts = [r for r in receipts if r.get("status", "").startswith("error")]
    for receipt in failed_receipts:
        blockers.append(
            f"input {Path(receipt['source']).name} failed intake parsing: {receipt.get('error')}"
        )
    if risks and not downstream_supported:
        blockers.append(
            "no risks in a downstream-supported taxonomy "
            f"({DOWNSTREAM_TAXONOMY}); scenario generation is blocked while "
            f"other taxonomies remain visible: {sorted(per_taxonomy)}"
        )
    if not llm_calls and not _is_no_llm_attempt(attempt_dir):
        gaps.append(
            "native extraction contains no llm_calls evidence; model-call "
            "capture is missing for a grounded run"
        )
    for tax in sorted(per_taxonomy):
        if tax != DOWNSTREAM_TAXONOMY:
            gaps.append(
                f"taxonomy {tax} ({per_taxonomy[tax]} risks) is not supported "
                "downstream by the Scenario Generator's risk loader in this "
                "configuration; recorded, not silently discarded"
            )
    if agentic_removed:
        gaps.append(
            "agentic-risk candidates were removed before retrieval because no "
            "document used agent terminology; a short policy cannot produce "
            "agentic-risk matches in this run"
        )

    return {
        "supplied_documents": supplied,
        "represented_documents": represented,
        "source_documents_native": source_documents,
        "intake_receipts": len(receipts),
        "risks_total": len(risks),
        "risks_per_taxonomy": per_taxonomy,
        "risks_downstream_supported": len(downstream_supported),
        "downstream_supported_taxonomy": DOWNSTREAM_TAXONOMY,
        "agentic_filter_removed_candidates": agentic_removed,
        "agentic_filter_basis": "native stderr/stats where available; else unknown",
        "llm_calls_recorded": len(llm_calls),
        "token_usage": extraction.get("token_usage"),
        "gaps": gaps,
        "blockers": blockers,
    }


def _is_no_llm_attempt(attempt_dir: Path) -> bool:
    meta = attempt_dir / "attempt.json"
    if meta.is_file():
        return bool(json.loads(meta.read_text(encoding="utf-8")).get("no_llm_mode"))
    return False
