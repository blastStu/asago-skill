# Asago skill: policy-to-Garak runner

A portable agent skill backed by a Python runner that takes policy documents
through the real [Asago](https://github.com/asago-ai) components — Policy
Mapper, Scenario Generator, Artifact Generator — to real
[Garak](https://github.com/NVIDIA/garak) results against an OpenAI-compatible
Chat Completions endpoint.

- **SKILL.md** is the agent-facing entry point (portable across harnesses).
- **`asago-runner`** (this package) is the deterministic orchestrator: it
  invokes the components as isolated subprocesses, retains native outputs and
  durable evidence, manages the IBM AI Atlas Nexus data cache, and keeps
  operational telemetry (OpenTelemetry) separate from audit evidence (files).
- **references/** holds setup instructions, the compatibility record and the
  review guide. **examples/** holds a labelled synthetic policy and system
  context plus a secret-free run configuration template.

Status, scope and the phased plan live in `design-docs/implementation-plan.md`.
Phase 1 delivers the working policy-to-Garak chain; OSCAL export is Phase 2.

## Quick start

```bash
uv sync --locked                 # runner + Asago component environment
uv run --project garak-env --locked sync   # separate pinned Garak environment
```

Then follow SKILL.md, or drive the runner directly (see
`references/cli.md`). Every stage command prints a machine-readable JSON
outcome and uses distinct exit codes so an incomplete stage can never be
mistaken for success.
