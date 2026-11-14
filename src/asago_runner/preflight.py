"""LLM-free readiness preflight.

Checks files/formats, output permissions, effective non-secret configuration,
credential presence, component entry points, the Garak environment, Nexus
dependency/data pairing (fetch + verify + native loader), capability/facts
schema validation against the native models, and the SSSOM mapping contract.
Produces a data-flow table for the input-readiness review. No inference
requests are made; local parser/retrieval model downloads are labelled
separately when detected.
"""

from __future__ import annotations

import importlib
import importlib.metadata as im
import json
import os
import shutil
from pathlib import Path
from typing import Any

from .config import RunConfig
from .evidence import RunDir, atomic_write_json
from .hashing import sha256_file
from .intake import SUPPORTED_SUFFIXES
from .nexus import NexusError, ensure_nexus_cache, exercise_native_loader

# All connection roles (generation + evaluation). A proposed-design run
# only uses the first two.
ROLES_ALL = ("mapper_llm", "scenario_llm", "artifact_llm", "target", "judge")

_CHECKS: list[dict] = []


def _check(name: str, ok: bool, detail: Any = None, blocker: bool = True) -> bool:
    _CHECKS.append(
        {
            "check": name,
            "ok": bool(ok),
            "detail": detail,
            "blocker": blocker and not ok,
        }
    )
    return bool(ok)


def garak_commit(garak_env_dir: Path) -> tuple[str | None, str | None]:
    """Read the garak install commit from the garak environment."""
    import subprocess

    garak_python = garak_env_dir / ".venv" / "bin" / "python"
    if not garak_python.is_file():
        return None, "garak environment not installed"
    proc = subprocess.run(
        [
            str(garak_python),
            "-c",
            "import json,importlib.metadata as im;"
            "d=im.distribution('garak');"
            "print(json.dumps({'version': d.version,"
            " 'commit': json.loads(d.read_text('direct_url.json'))"
            ".get('vcs_info',{}).get('commit_id')}))",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        return None, proc.stderr.strip()[:200] or "garak metadata read failed"
    info = json.loads(proc.stdout.strip())
    return info.get("commit"), info.get("version")


def run_preflight(
    run: RunDir,
    config: RunConfig,
    cache_dir: Path,
    garak_env_dir: Path,
    *,
    fetch_nexus: bool = True,
) -> dict:
    """Run all preflight checks; returns a report dict."""
    _CHECKS.clear()

    # 1. Inputs exist and formats are supported.
    for policy_path in config.policy_paths():
        exists = policy_path.is_file()
        supported = policy_path.suffix.lower() in SUPPORTED_SUFFIXES
        _check(
            f"policy.exists.{policy_path.name}",
            exists,
            str(policy_path) if not exists else None,
        )
        _check(
            f"policy.format.{policy_path.name}",
            supported,
            f"unsupported suffix {policy_path.suffix}" if not supported else None,
        )
    system_section = config.raw.get("system", {})
    supplied = [("use-case", config.resolved_path("use_case_file"))]
    for key, label in (
        ("profile_file", "profile"),
        ("qualification_facts_file", "qualification-facts"),
    ):
        if system_section.get(key):
            supplied.append((label, config.resolved_path(key)))
    supplied.append(("sssom", config.sssom_path()))
    for label, path in supplied:
        _check(f"input.exists.{label}", path.is_file(), str(path))

    # 2. Output location writable.
    probe = run.path / ".write-probe"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        _check("run.writable", True)
    except OSError as exc:
        _check("run.writable", False, str(exc))

    # 3. Component entry points present in the runner environment.
    from .paths import component_cli

    for cli in (
        "asago-policy-mapper",
        "asago-scenario-generator",
        "asago-artifact-generator",
    ):
        try:
            resolved = component_cli(cli)
            _check(f"component.cli.{cli}", True, resolved)
        except FileNotFoundError as exc:
            _check(f"component.cli.{cli}", False, str(exc))

    # 4. Credential presence (values never recorded). For a proposed-design
    #    run the pipeline stops after the Scenario Generator, so only the
    #    generation roles the run actually uses need connections.
    downstream_roles = () if config.subject == "proposed" else ROLES_ALL
    required_roles = ("mapper_llm", "scenario_llm") + tuple(
        r for r in ("artifact_llm", "target", "judge") if r in downstream_roles
    )
    for role, spec in config.connections.items():
        if role not in required_roles:
            _check(
                f"credentials.{role}",
                True,
                "not required: design-time run (subject: proposed) stops after "
                "the Scenario Generator",
                blocker=False,
            )
            continue
        values = spec.resolve()
        _check(
            f"credentials.{role}",
            bool(values["base_url"]) and bool(values["model"]) and bool(values["api_key"]),
            {
                "base_url_env_set": bool(values["base_url"]),
                "model_env_set": bool(values["model"]),
                "api_key_env_set": bool(values["api_key"]),
                "env_names": [spec.base_url_env, spec.model_env, spec.api_key_env],
            },
        )

    # 5. Nexus dependency/data pairing: fetch, verify, exercise loader.
    nexus_report: dict | None = None
    try:
        result = ensure_nexus_cache(cache_dir, fetch=fetch_nexus)
        loader = exercise_native_loader(Path(result.cache_dir))
        result.loader = loader
        nexus_report = result.summary()
        _check("nexus.dependency-data-pairing", True, nexus_report)
        _check(
            "nexus.loader-counts-agree",
            loader.get("counts_agree", False),
            "sparse cache load must agree with the installed-package-only load",
        )
    except NexusError as exc:
        _check("nexus.dependency-data-pairing", False, str(exc))

    # 6. Garak environment present and pinned. Not required for
    #    design-time runs: evaluation is out of scope when the subject is
    #    a proposed design.
    garak_python = garak_env_dir / ".venv" / "bin" / "python"
    design_note = (
        "not required: design-time run (subject: proposed) stops after "
        "the Scenario Generator"
        if config.subject == "proposed"
        else None
    )
    _check(
        "garak.environment",
        garak_python.is_file() or design_note is not None,
        design_note or str(garak_python),
        blocker=design_note is None,
    )
    if garak_python.is_file():
        commit, version = garak_commit(garak_env_dir)
        _check(
            "garak.pinned-commit",
            commit == "06aba1a2c9b142d561eeeff08dfaffcbe77487c3",
            f"installed at {commit} (version {version})"
            + (
                " — not blocking: design-time run never evaluates"
                if config.subject == "proposed"
                else ""
            ),
            blocker=config.subject != "proposed",
        )

    # 7. Capability profile + qualification facts are OPTIONAL user inputs.
    #    When supplied they are validated against the native pydantic models
    #    (model-free). When absent, the Scenario Generator runs its own
    #    Stage-1 inference — noted honestly, never fabricated here.
    if config.raw.get("system", {}).get("profile_file"):
        try:
            from asago_scenario_generator.models.capability_profile import CapabilityProfile

            import yaml

            profile_data = yaml.safe_load(
                config.resolved_path("profile_file").read_text(encoding="utf-8")
            )
            CapabilityProfile.model_validate(profile_data)
            _check("scenario.profile-schema", True)
        except Exception as exc:  # noqa: BLE001
            _check("scenario.profile-schema", False, str(exc))
    else:
        _check(
            "scenario.profile-optional-absent",
            True,
            "no capability profile supplied: the Scenario Generator's "
            "Stage-1 inference will run, but an inferred profile cannot "
            "provide Stage-2 inventory evidence (external_integrations, "
            "trust_boundaries). If the selected risks require those "
            "categories, projection aborts after the mapper has run and the "
            "scenarios stage returns a needs-review request asking for a "
            "reviewed profile. Supply a reviewed profile up front to avoid "
            "that cost — especially for design-time runs.",
            blocker=False,
        )
    facts_config = config.raw.get("system", {}).get("qualification_facts_file")
    if facts_config:
        try:
            facts = yaml.safe_load(
                config.resolved_path("qualification_facts_file").read_text(encoding="utf-8")
            )
            has_facts = isinstance(facts, dict) and isinstance(facts.get("facts"), list)
            _check(
                "scenario.facts-schema",
                has_facts,
                None if has_facts else "facts must be a list under 'facts'",
            )
        except Exception as exc:  # noqa: BLE001
            _check("scenario.facts-schema", False, str(exc))
    else:
        _check(
            "scenario.facts-optional-absent",
            True,
            "no qualification facts supplied: unresolved conditions are "
            "deferred to authoritative projection (omitted_compatibility)",
            blocker=False,
        )

    # 8. SSSOM mapping contract with the native loader/index.
    try:
        from asago_scenario_generator.data.sssom import load_sssom

        mappings = load_sssom(config.sssom_path())
        subjects = {m.subject_id for m in mappings}
        predicates: dict[str, int] = {}
        for mapping in mappings:
            predicates[mapping.predicate_id] = predicates.get(mapping.predicate_id, 0) + 1
        _check(
            "sssom.native-load",
            bool(mappings),
            {"count": len(mappings), "predicates": predicates},
        )
        if config.selected_risk_ids:
            missing = [rid for rid in config.selected_risk_ids if rid not in subjects]
            _check(
                "sssom.selected-risks-mapped",
                not missing,
                f"selected risk IDs without a mapping row: {missing}",
            )
    except Exception as exc:  # noqa: BLE001
        _check("sssom.native-load", False, str(exc))

    # 8b. Reviewed tool schema (optional): resolvable and shaped like a
    #     tool contract when supplied.
    if config.tools_schema_file:
        try:
            schema_path = config._resolve(config.tools_schema_file)
            tools = json.loads(schema_path.read_text(encoding="utf-8")).get("tools", [])
            ok_tools = isinstance(tools, list) and all(
                isinstance(t, dict) and isinstance(t.get("function"), dict)
                for t in tools
            )
            _check(
                "tools.reviewed-schema",
                ok_tools,
                f"{len(tools)} reviewed tool schemas at {run.rel(schema_path)}"
                if ok_tools
                else "tools schema must be a list of function-tool objects",
            )
        except Exception as exc:  # noqa: BLE001
            _check("tools.reviewed-schema", False, str(exc))

    # 9. Local retrieval/parser assets (labelled, informational).
    hf_home = Path(
        os.environ.get("HF_HOME", Path.home() / ".cache" / "huggingface")
    )
    retrieval = config.raw.get("retrieval") or {}
    bi_encoder = retrieval.get("bi_encoder_model", "all-mpnet-base-v2")
    cached = any(
        (hf_home / "hub").glob(f"models--*--{bi_encoder.replace('/', '--')}*")
    ) if (hf_home / "hub").is_dir() else False
    _check(
        "assets.local-retrieval-models",
        True,  # informational: download happens on first map stage if absent
        {
            "bi_encoder": bi_encoder,
            "cached_locally": cached,
            "note": (
                "local model download on first use is an asset fetch, not an "
                "inference request" + ("" if cached else "; first map stage will download")
            ),
        },
        blocker=False,
    )

    blockers = [c for c in _CHECKS if c["blocker"]]
    advisories = [
        c["detail"]
        for c in _CHECKS
        if c["check"]
        in ("scenario.profile-optional-absent", "scenario.facts-optional-absent")
        and c.get("detail")
    ]
    report = {
        "ok": not blockers,
        "checks": _CHECKS,
        "blockers": blockers,
        "advisories": advisories,
        "subject": config.subject,
        "subject_note": (
            "design-time run: the subject is a proposed design; the pipeline "
            "stops after the Scenario Generator and reports the threat picture"
            if config.subject == "proposed"
            else "the subject is a built system; the full chain including "
            "evaluation is in scope"
        ),
        "data_flow": config.data_flow_table(),
        "shared_model_roles": config.shared_model_roles(),
        "note": (
            "preflight performs no inference requests; connection smoke checks "
            "are separate, labelled operations"
        ),
    }
    atomic_write_json(run.path / "preflight" / "preflight.json", report)
    return report
