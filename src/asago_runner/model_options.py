"""Detect model connections available in the agent's own environment.

When an agent harness runs the skill, its process environment often already
holds an endpoint and credentials for the model the agent itself is using
(for example ``ANTHROPIC_BASE_URL``/``ANTHROPIC_API_KEY``, or the OpenAI
equivalents). Those may be usable for Asago's model roles, which would save
the user configuring a separate connection.

This module only *detects and describes* candidates. It never selects one,
never assumes one is usable, and never prints a secret value. Compatibility
with the OpenAI Chat Completions API cannot be proven from an environment
variable, so every candidate is marked with an assessment that the skill
must present to the user and, before a live run, verify with a labelled
smoke request (see ``references/compatibility-record.md``).
"""

from __future__ import annotations

import os
from typing import Any

from .config import ROLES, _host_of

# Variables that commonly describe an agent harness's own model connection.
# Only names are read; values are never recorded or printed.
_AGENT_SOURCES = (
    {
        "source": "anthropic-style agent",
        "base_url_env": "ANTHROPIC_BASE_URL",
        "api_key_envs": ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"),
        "model_envs": (
            "ANTHROPIC_MODEL",
            "ANTHROPIC_DEFAULT_SONNET_MODEL",
            "ANTHROPIC_DEFAULT_OPUS_MODEL",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL",
        ),
    },
    {
        "source": "openai-style agent",
        "base_url_env": "OPENAI_BASE_URL",
        "api_key_envs": ("OPENAI_API_KEY",),
        "model_envs": ("OPENAI_MODEL",),
    },
)


def _first_set(names: tuple[str, ...]) -> tuple[str | None, str | None]:
    """Return (first set variable name, its value) without exposing it."""
    for name in names:
        value = os.environ.get(name)
        if value:
            return name, value
    return None, None


def _compat_assessment(source: str, base_url: str | None) -> tuple[str, str]:
    """A conservative, honest compatibility assessment (never a guarantee)."""
    if not base_url:
        return (
            "unknown",
            "no base URL detected; ask the user for the endpoint",
        )
    host = (_host_of(base_url) or "").lower()
    if "api.anthropic.com" in host:
        return (
            "unlikely",
            "the Anthropic Messages API is not the OpenAI Chat Completions "
            "API; Asago's components need an OpenAI-compatible endpoint "
            "(many gateways are; api.anthropic.com is not)",
        )
    if source.startswith("openai") or "api.openai.com" in host:
        return ("likely", "an OpenAI Chat Completions endpoint")
    return (
        "unknown",
        "custom gateway: compatibility must be verified with a labelled "
        "smoke request (structured output, token parameters, tools) before "
        "a live run",
    )


def detect_model_options() -> dict[str, Any]:
    """Describe model connections the current environment appears to expose."""
    candidates = []
    for spec in _AGENT_SOURCES:
        base_url = os.environ.get(spec["base_url_env"])
        key_name, _key_value = _first_set(spec["api_key_envs"])
        model_name, model_value = _first_set(spec["model_envs"])
        if not base_url and not key_name:
            continue
        compat, compat_note = _compat_assessment(spec["source"], base_url)
        candidates.append(
            {
                "source": spec["source"],
                "base_url_env": spec["base_url_env"],
                "base_url_present": bool(base_url),
                "base_url_host": _host_of(base_url),
                "api_key_env": key_name,
                "api_key_present": bool(key_name),
                "model_env": model_name,
                "model": model_value,
                "openai_compat": compat,
                "openai_compat_note": compat_note,
            }
        )
    return {
        "candidates": candidates,
        "roles_needed": list(ROLES),
        "note": (
            "Detected from the environment this agent runs in. Present these "
            "to the user as an OPTION — never select one silently. They are "
            "the agent's own credentials (usage bills to that account), and "
            "compatibility is not proven by an environment variable: verify "
            "with a labelled smoke request before a live run."
        ),
    }


def render_model_options(detected: dict[str, Any]) -> str:
    """Human-readable summary for the agent to present (no secret values)."""
    lines = ["Model connections detected in this agent's environment:", ""]
    candidates = detected.get("candidates", [])
    if not candidates:
        lines.append(
            "  None detected. Ask the user for an endpoint and credentials."
        )
    for index, candidate in enumerate(candidates, start=1):
        lines.append(
            f"  Option {index}: {candidate['source']} — "
            f"{candidate.get('base_url_host') or '(no base URL)'}"
        )
        if candidate.get("model"):
            lines.append(f"      model: {candidate['model']} (from {candidate['model_env']})")
        lines.append(
            "      credentials: "
            + (
                f"available via ${candidate['api_key_env']} (value never shown)"
                if candidate.get("api_key_present")
                else "not detected — the user must supply them"
            )
        )
        lines.append(
            f"      OpenAI-compatible: {candidate['openai_compat']} — "
            f"{candidate['openai_compat_note']}"
        )
        lines.append(
            f"      use by naming these variables in the run configuration: "
            f"{candidate['base_url_env']}"
            + (f", {candidate['model_env']}" if candidate.get("model_env") else "")
            + (f", {candidate['api_key_env']}" if candidate.get("api_key_env") else "")
        )
        lines.append("")
    lines.append(
        "These are options, not assumptions: offer the user the agent's "
        "endpoint alongside their own choice, and verify compatibility with a "
        "labelled smoke request before a live run."
    )
    return "\n".join(lines)
