# Setup

## Prerequisites

- [uv](https://docs.astral.sh/uv/) (Python 3.13 is managed by uv)
- Network access to GitHub (component pins are git dependencies) and, on
  first use, to Hugging Face for the mapper's local retrieval models and
  Docling parser models (local asset downloads, not inference requests)
- Model credentials for the live stages (see below)

## Install the two locked environments

From the skill root:

```bash
uv sync --locked                              # runner + Asago components
uv run --project garak-env --locked sync      # pinned Garak environment
```

The first environment contains the runner (`asago-runner`) plus the real
Policy Mapper, Scenario Generator and Artifact Generator at immutable
commits. The second contains the pinned Garak fork. The split exists because
the Garak fork and the Policy Mapper have disjoint version constraints
(numpy, transformers); the two environments exchange files only.

Verify the installation:

```bash
.venv/bin/asago-runner preflight <run-dir>   # after creating a run (see cli.md)
```

Preflight checks component entry points, the pinned Garak commit,
credentials presence (names only), input formats and the Nexus data pairing.

## IBM AI Atlas Nexus data (automatic)

The Policy Mapper requires a local Nexus data clone matching the installed
`ai-atlas-nexus` dependency revision. **Users do not need to find or
maintain one**: preflight resolves the effective installed dependency
(`importlib.metadata` + `direct_url.json` VCS commit, cross-checked against
the import location), fetches the required tracked data files at exactly
that commit into a runner-managed cache (default `.cache/nexus/<commit>/`,
override with `--cache-dir`), and passes the managed path through the
mapper's supported `--nexus-base-dir` setting.

The cache is a sparse checkout of `src/ai_atlas_nexus/data` — the complete
file set the native loader (`AIAtlasNexus(base_dir=...).get_all_risks()`,
which merges by entity id) and the mapper's mitigation enrichment read.
Completeness is validated by exercising the loader and comparing its output
with the installed-package-only load. Verification includes:

- every cached file hash matches the recorded manifest (detects local
  modification; a Git tree ID alone would not);
- no unmanifested data files (detects injected extras);
- the cache Git HEAD equals the required commit;
- the installed distribution's bundled data matches the fetched revision
  bytes (content provenance of the installation itself);
- the native load path runs with the mapper CLI's taxonomy exclusions and
  description overrides, recording counts before and after filtering.

A wheel without VCS metadata is reported as unverifiable rather than passed
on a version label. Mismatched, modified or unverifiable data, or an
unavailable pinned commit, stops preflight with an actionable blocker —
never a silent fallback to another revision.

## Credentials

Secrets live only in the environment; the run configuration records
variable names. For the example configuration:

```bash
export MAPPER_BASE_URL=...   MAPPER_MODEL=...   MAPPER_API_KEY=...
export SCENARIO_BASE_URL=... SCENARIO_MODEL=... SCENARIO_API_KEY=...
export ARTIFACT_BASE_URL=... ARTIFACT_MODEL=... ARTIFACT_API_KEY=...
export TARGET_BASE_URL=...   TARGET_MODEL=...   TARGET_API_KEY=...
export JUDGE_BASE_URL=...    JUDGE_MODEL=...    JUDGE_API_KEY=...
```

All model roles use OpenAI-compatible Chat Completions endpoints. Roles may
share a connection; shared target/judge models are recorded as a lack of
independent validation. The mapper's retrieval models default to local
CPU models (downloaded on first use); remote embedding/reranker endpoints
can be configured under `retrieval:` in the run configuration.

## Reusing the agent's own endpoint

If the agent harness already has an endpoint and credentials in its
environment, you may reuse them for Asago's roles instead of configuring a
separate connection. Run:

```bash
.venv/bin/asago-runner model-options
```

It reports what is available (`ANTHROPIC_BASE_URL`/`ANTHROPIC_API_KEY` or the
OpenAI equivalents), the host and model, and a conservative compatibility
assessment — never a secret value. Naming those variables in the run
configuration makes the runner resolve them at stage time, so the values
never enter a file or the evidence. Reusing the agent's credentials bills
usage to that account, and compatibility still has to be verified with a
labelled smoke request before a live run (an environment variable cannot
prove the endpoint speaks Chat Completions).

## Choosing models per role

Bring whichever models you want — each role only needs to support the
request shapes that role actually sends. The requirements below come from
the pinned components' behaviour (see
`references/compatibility-record.md` for the measured background); when a
model does not meet one, the stage fails honestly with a recorded reason
rather than degrading silently.

| Role | The model must support | Typical failure if not |
| --- | --- | --- |
| **mapper_llm** | Structured output via `response_format: json_schema`; whichever output-token parameter and temperature you configure (`options.mapper_output_token_parameter`, `options.mapper_temperature` — e.g. some models accept only `max_completion_tokens` and `temperature=1`) | HTTP 400 on unsupported parameters; set the matching option |
| **scenario_llm** | Strict `json_schema` including less-common JSON Schema keywords (e.g. `maxProperties`), **and** structured drafts that fit the component's hardcoded per-call completion caps (4096 tokens for actor-profile/behavior/filter calls, 8192 for narrative/attack-tree — an operator transport cap can only lower these) | Schema-rejecting endpoints return HTTP 400; verbose or reasoning-heavy models hit `CompletionLengthError` and candidates are quarantined |
| **artifact_llm** | The generator hardcodes `temperature=0.2` (no override) and your configured completion limit (`options.artifact_max_completion_tokens`) | Models that accept only `temperature=1` fail every artifact call |
| **target** | Chat Completions with the replay's message shapes; for tool-return replay also declared `tools`, prior `assistant.tool_calls` and `role=tool` messages | Refusal/400 at evaluation; tool-message replay needs the shapes verified (the runner's labelled smoke checks do this) |
| **judge** | Plain chat completion returning parseable JSON `{"success": 0-100, "reasoning": ...}` | Non-JSON or empty responses make the evaluation `inconclusive` (never a false verdict) |

The Policy Mapper issues up to 32 parallel model calls by default. If that
floods a home network or a rate-limited endpoint, set
`options.mapper_max_concurrent` to a lower positive integer; it is passed as
`--max-concurrent` and recorded in the stage dispatch receipt. Omitting it
keeps the component default. (The Scenario Generator exposes no such
setting.)

A quick way to sanity-check a candidate model before a full run: replay the
labelled smoke checks (schema, temperature/token parameters, tools + prior
tool messages) as shown in the compatibility record — a few one-token
requests, no policy content.

## Optional inputs and reviewed tool schemas

The capability profile and qualification facts are optional; without them
the Scenario Generator runs its own Stage-1 inference (see
`examples/config.example.yaml`). Two further optional settings:

- `retrieval:` — remote bi-/cross-encoder endpoints for the Policy Mapper
  (defaults are local CPU models). A remote endpoint means policy chunk
  text is sent there; it appears in the data-flow table.
- `options.tools_schema_file` — a JSON file with a top-level `tools` list
  of OpenAI function-tool objects, used as the typed contract for replayed
  tool calls. It is copied into the run at `new-run`, validated for shape
  at `preflight`, and must name exactly the tools the artifact's own
  system-turn declarations name (a mismatch rejects the replay entry).
  Without it, schemas are derived from those declarations only.

## Telemetry (optional)

Runner/stage spans export through the standard OpenTelemetry settings —
set `OTEL_EXPORTER_OTLP_ENDPOINT` (and optionally `OTEL_SERVICE_NAME`).
The user provides the Collector; no backend is provisioned. Without an
endpoint, telemetry is disabled with a recorded warning and evidence is
unaffected. Content (prompts, responses, policy text) is never exported.

## Environment isolation

Components run as subprocesses with an environment **allowlist** (platform
basics plus exactly the variables each stage needs), a clean working
directory, and an optional parent-enforced wall-clock deadline (none by
default) with process-group
cleanup. Unrelated provider keys cannot leak into or reroute a stage, and
the Artifact Generator's `.env` auto-discovery finds nothing: its
code-root location resolves inside the managed venv (no `.env`) and the
cwd is a fresh stage directory. Provider selection for artifact generation
is always explicit (`REDTEAM_PROVIDER=openai`).

## Offline checks

```bash
.venv/bin/python -m pytest tests/ -q
```

covers eligibility/transport rules, tool-schema derivation, evidence tree
behaviour, subprocess isolation/deadlines, intake receipts, reconciliation
span maps, review bindings, Nexus cache tampering, and the E4 stub-server
Garak failure matrix (judge 400, malformed judgment, target 500/hang under
the parent deadline). The live policy-to-Garak acceptance run is separate
and explicit — see `references/compatibility-record.md`.
