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

## Telemetry (optional)

Runner/stage spans export through the standard OpenTelemetry settings —
set `OTEL_EXPORTER_OTLP_ENDPOINT` (and optionally `OTEL_SERVICE_NAME`).
The user provides the Collector; no backend is provisioned. Without an
endpoint, telemetry is disabled with a recorded warning and evidence is
unaffected. Content (prompts, responses, policy text) is never exported.

## Environment isolation

Components run as subprocesses with an environment **allowlist** (platform
basics plus exactly the variables each stage needs), a clean working
directory, and a parent-enforced wall-clock deadline with process-group
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
