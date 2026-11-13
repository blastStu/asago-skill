"""Run configuration loading, validation and sanitisation.

Secrets never appear in the configuration file or in retained evidence: each
connection names the environment variables that hold its values at run time.
The runner records variable *names* plus sanitised non-secret settings
(model names in full, endpoint hosts only).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

CONFIG_SCHEMA_VERSION = 1

ROLES = ("mapper_llm", "scenario_llm", "artifact_llm", "target", "judge")


class ConfigError(ValueError):
    """The run configuration is invalid."""


@dataclass
class ConnectionSpec:
    """A model connection described by environment variable names."""

    role: str
    base_url_env: str
    model_env: str
    api_key_env: str | None = None
    extra_headers_env: str | None = None

    def resolve(self) -> dict[str, str | None]:
        """Resolve current values from the environment (secrets stay memory-only)."""
        key = os.environ.get(self.api_key_env) if self.api_key_env else None
        return {
            "base_url": os.environ.get(self.base_url_env),
            "model": os.environ.get(self.model_env),
            "api_key": key,
        }

    def sanitized(self) -> dict[str, Any]:
        """Recordable description: env var names, model name, endpoint host."""
        values = self.resolve()
        return {
            "role": self.role,
            "base_url_env": self.base_url_env,
            "model_env": self.model_env,
            "api_key_env": self.api_key_env,
            "model": values["model"],
            "base_url_host": _host_of(values["base_url"]),
            "api_key_present": bool(values["api_key"]),
        }


def _host_of(base_url: str | None) -> str | None:
    if not base_url:
        return None
    try:
        parsed = urlparse(base_url)
        return parsed.hostname or parsed.path.split("/")[0] or None
    except ValueError:
        return None


@dataclass
class RunConfig:
    """Validated run configuration."""

    source_path: Path
    raw: dict
    path_map: dict[str, str] = field(default_factory=dict)
    connections: dict[str, ConnectionSpec] = field(default_factory=dict)
    subject: str = "built"  # built | proposed
    selected_risk_ids: list[str] | None = None
    generation_mode: str = "coverage"
    max_scenarios_per_pattern: int | None = 2
    max_artifacts: int = 3
    target_samples_per_artifact: int = 1
    stage_deadline_seconds: int = 3600
    ocr: bool = False
    telemetry_enabled: bool = True
    tools_schema_file: str | None = None

    # -- loading ---------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path, path_map: dict[str, str] | None = None) -> "RunConfig":
        """Load a configuration.

        ``path_map`` maps config-relative input paths to their actual
        locations — used when loading the copied configuration inside a run
        directory, whose originals live under ``originals/`` subsections.
        """
        source = Path(path).resolve()
        if not source.is_file():
            raise ConfigError(f"configuration file not found: {source}")
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ConfigError("configuration must be a YAML mapping")
        if raw.get("schema_version") != CONFIG_SCHEMA_VERSION:
            raise ConfigError(
                f"unsupported schema_version {raw.get('schema_version')!r}; "
                f"expected {CONFIG_SCHEMA_VERSION}"
            )
        cfg = cls(source_path=source, raw=raw, path_map=dict(path_map or {}))

        policy = _require_mapping(raw, "policy")
        docs = policy.get("documents")
        if not isinstance(docs, list) or not docs:
            raise ConfigError("policy.documents must be a non-empty list")
        for entry in docs:
            if not isinstance(entry, dict) or not entry.get("path"):
                raise ConfigError("each policy.documents entry needs a path")

        run_section = _require_mapping(raw, "run")
        cfg.subject = str(run_section.get("subject", "built")).strip().lower()
        if cfg.subject not in ("built", "proposed"):
            raise ConfigError(
                "run.subject must be 'built' (the system exists and can be "
                "evaluated end to end) or 'proposed' (a design description "
                "only: the run stops after the Scenario Generator)"
            )

        system = _require_mapping(raw, "system")
        for key in ("use_case_file", "profile_file", "qualification_facts_file"):
            if not system.get(key):
                raise ConfigError(f"system.{key} is required")
        identity = system.get("identity") or {}
        if not identity.get("system_name"):
            raise ConfigError("system.identity.system_name is required")

        sssom = _require_mapping(raw, "sssom")
        if not sssom.get("path"):
            raise ConfigError("sssom.path is required")

        connections = _require_mapping(raw, "connections")
        for role in ROLES:
            spec = connections.get(role)
            if not isinstance(spec, dict):
                raise ConfigError(f"connections.{role} is required")
            for env_name in ("base_url_env", "model_env"):
                if not spec.get(env_name):
                    raise ConfigError(f"connections.{role}.{env_name} is required")
            cfg.connections[role] = ConnectionSpec(
                role=role,
                base_url_env=spec["base_url_env"],
                model_env=spec["model_env"],
                api_key_env=spec.get("api_key_env"),
                extra_headers_env=spec.get("extra_headers_env"),
            )

        scope = raw.get("scope") or {}
        cfg.selected_risk_ids = scope.get("risk_ids") or None
        cfg.generation_mode = scope.get("generation_mode", "coverage")
        if cfg.generation_mode not in ("coverage", "exhaustive"):
            raise ConfigError("scope.generation_mode must be 'coverage' or 'exhaustive'")
        cfg.max_scenarios_per_pattern = scope.get("max_scenarios_per_pattern", 2)
        cfg.max_artifacts = int(scope.get("max_artifacts", 3))
        cfg.target_samples_per_artifact = int(scope.get("target_samples_per_artifact", 1))
        cfg.stage_deadline_seconds = int(scope.get("stage_deadline_seconds", 3600))

        options = raw.get("options") or {}
        cfg.ocr = bool(options.get("ocr", False))
        cfg.telemetry_enabled = bool((raw.get("telemetry") or {}).get("enabled", True))
        cfg.tools_schema_file = options.get("tools_schema_file")
        return cfg

    # -- accessors --------------------------------------------------------

    def _resolve(self, config_rel: str) -> Path:
        if config_rel in self.path_map:
            return Path(self.path_map[config_rel]).resolve()
        return (self.source_path.parent / config_rel).resolve()

    def policy_paths(self) -> list[Path]:
        return [self._resolve(entry["path"]) for entry in self.raw["policy"]["documents"]]

    def resolved_path(self, key: str, section: str = "system") -> Path:
        return self._resolve(self.raw[section][key])

    def sssom_path(self) -> Path:
        return self._resolve(self.raw["sssom"]["path"])

    def sanitized_snapshot(self) -> dict:
        """A recordable copy of the configuration: no secret values."""
        raw = yaml.safe_load(self.source_path.read_text(encoding="utf-8"))
        snapshot = {
            "schema_version": CONFIG_SCHEMA_VERSION,
            "config_source": self.source_path.name,
            "config_sha256": _file_sha(self.source_path),
            "subject": self.subject,
            "policy_documents": [
                {"path": p.name, "sha256": _file_sha(p)} for p in self.policy_paths()
            ],
            "connections": {
                role: spec.sanitized() for role, spec in self.connections.items()
            },
            "shared_model_roles": self.shared_model_roles(),
            "scope": {
                "risk_ids": self.selected_risk_ids,
                "generation_mode": self.generation_mode,
                "max_scenarios_per_pattern": self.max_scenarios_per_pattern,
                "max_artifacts": self.max_artifacts,
                "target_samples_per_artifact": self.target_samples_per_artifact,
                "stage_deadline_seconds": self.stage_deadline_seconds,
            },
            "options": {
                "ocr": self.ocr,
                "tools_schema_file": self.tools_schema_file,
            },
            "telemetry_enabled": self.telemetry_enabled,
            "raw_non_secret": _sanitize_value(raw),
        }
        return snapshot

    def shared_model_roles(self) -> list[list[str]]:
        """Groups of roles that resolve to the same model+host (lack of independence)."""
        groups: dict[tuple[str, str], list[str]] = {}
        for role, spec in self.connections.items():
            values = spec.resolve()
            if values["model"] and values["base_url"]:
                groups.setdefault((values["model"], _host_of(values["base_url"])), []).append(role)
        return [sorted(members) for members in groups.values() if len(members) > 1]

    def data_flow_table(self) -> list[dict]:
        """Which configured provider receives which content, per stage role."""
        flows = {
            "mapper_llm": "policy text (chunk groups, queries, candidate risks)",
            "mapper_retrieval": "policy chunk text (local embedding/rerank models by default)",
            "scenario_llm": "use case, capability profile, risk descriptions, qualification facts",
            "artifact_llm": "scenario narrative, attack tree, behavior spec",
            "target": "prepared conversation turns incl. attack content",
            "judge": "attack criteria, target response text and tool-call proposals",
        }
        rows = []
        for role, spec in self.connections.items():
            values = spec.resolve()
            if self.subject == "proposed" and role in ("artifact_llm", "target", "judge"):
                rows.append(
                    {
                        "role": role,
                        "receives": "not applicable — design-time run stops after the Scenario Generator",
                        "provider_host": None,
                        "model": None,
                    }
                )
                continue
            rows.append(
                {
                    "role": role,
                    "receives": flows.get(role, ""),
                    "provider_host": _host_of(values["base_url"]),
                    "model": values["model"],
                }
            )
        rows.append(
            {
                "role": "mapper_retrieval",
                "receives": flows["mapper_retrieval"],
                "provider_host": "local (default models; see compatibility record)",
                "model": (self.raw.get("retrieval") or {}).get(
                    "bi_encoder_model", "all-mpnet-base-v2"
                ),
            }
        )
        return rows


def _require_mapping(raw: dict, key: str) -> dict:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise ConfigError(f"{key} section is required")
    return value


def _file_sha(path: Path) -> str:
    from .hashing import sha256_file

    return sha256_file(path)


_SECRET_KEY_RE = re.compile(r"(key|token|secret|password|authorization)", re.I)


def _sanitize_value(value: Any) -> Any:
    """Drop values whose keys look secret; keep structure for the record."""
    if isinstance(value, dict):
        return {
            k: ("<redacted>" if _SECRET_KEY_RE.search(str(k)) else _sanitize_value(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_value(v) for v in value]
    return value
