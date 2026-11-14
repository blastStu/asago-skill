# CLI contract

Every command prints a machine-readable JSON outcome as the final stdout
line and exits with:

| Code | Status | Meaning |
| --- | --- | --- |
| 0 | `completed` | stage finished |
| 4 | `completed_with_gaps` | stage finished; some items excluded/failed (visible in `gaps`) |
| 2 | `needs_review` | a review gate is pending; request file path in `review` |
| 3 | `blocked` | missing prerequisite/input; see `blockers` |
| 1 | `failed` | unexpected error; see `error` |

Outcome fields: `runner`, `runner_version`, `stage`, `run_dir`, `status`,
plus stage-specific fields (`attempt`, `accounting`, `inventory_summary`,
`replay_entries`, `evaluations`, `gaps`, `blockers`, `review`, `error`).

## Commands

```
asago-runner plan       [--subject built|proposed]
asago-runner model-options
asago-runner new-run --config <cfg.yaml> [--run-dir DIR] [--runs-root DIR]
                     [--cache-dir DIR]
asago-runner preflight  RUN [--response FILE] [--cache-dir DIR] [--garak-env DIR]
                     [--skip-nexus-fetch]
asago-runner intake     RUN [--response FILE]
asago-runner map        RUN [--no-llm]
asago-runner scenarios  RUN
asago-runner artifacts  RUN
asago-runner replay-review RUN [--response FILE]
asago-runner evaluate   RUN [--garak-env DIR]
asago-runner report     RUN
asago-runner verify-run RUN
asago-runner status     RUN
asago-runner log        RUN [--stage STAGE] [--lines N]
asago-runner watch      RUN [--stage STAGE] [--follow] [--interval N] [--json]
asago-runner respond    REQUEST --decision D [--actor A] [--notes N]
                        [--clarification TEXT] [--reconciliation-file FILE]
```

`model-options` inspects the environment the agent is running in and
reports any endpoint/credentials/model it exposes (secret values are never
printed; compatibility is only assessed, never assumed). The skill offers
the detected connection to the user as one option among several.

`plan` prints the canonical welcome plan (built or design-time variant). It
needs no run directory and is deterministic: the skill quotes it verbatim
(translating faithfully if needed) instead of composing its own plan, so
the journey is identical for every user and session.

`watch` classifies a running (or finished) stage deterministically:
`running`, `retrying`, `stalled` (log silent past the threshold), `failed`,
`blocked`, `done`, with elapsed time, retry/error counts, the last
milestone and the extracted error (e.g. `APIConnectionError: Connection
error.`). `--follow` prints a line on every change and exits when the stage
reaches a terminal state — run it in the background beside a long stage and
relay each line; retrying/stalled/failed are report-now events, not noise.

`log` tails the latest (or named) stage attempt's log — plain text, for
live progress updates while a long stage runs in the background.

`status` prints a progress checklist before its JSON line. Every step is
tagged with whose work it is — `[ASAGO COMPONENT]` for the real,
unmodified Asago libraries, `[EXTERNAL: GARAK]` for the external
evaluator, `[RUNNER]` for orchestration/bookkeeping/reporting, and
`[YOUR REVIEW]` for user decisions. The same distinction appears in the
offline HTML report's "Whose work" column. Agents should quote the
checklist (including its legend) when narrating progress.

`report` derives `reports/summary.json` and renders the offline
`reports/index.html`: a fifth-tab run report with one tab per pipeline
stage plus **05 Run audit**. Policy findings are grouped by theme using the
mapper's curated report navigation data (adopted from PR #79 at a pinned
commit) joined through the same SSSOM mappings the mapper uses. Stages a
design-time run does not reach are rendered disabled with their reason.
`--conversation <path>` (or `reports/conversation.md` in the run) embeds a
transcript of the session that ran the skill in the audit tab; it is
escaped, and the transcript text is not written into `summary.json`. The
page loads nothing from the network; its one inline script only switches
tabs, filters findings and toggles light/dark.

`RUN` is the run directory created by `new-run`. **Runs are isolated**: by
default `new-run` creates the run under `~/.asago/runs/<label>` (override
with `--runs-root` or `$ASAGO_RUNNER_RUNS_ROOT`, or place one explicitly
with `--run-dir`), outside the repository, so a run is never polluted by —
or distracts an agent with — prior runs. Each run directory is
self-contained (originals, config snapshot, evidence, reports), and stages
never read other runs. The pipeline order is the command order; each stage
refuses to run before its prerequisites are recorded (with actionable
blockers). `--no-llm` on `map` is the model-free
IR-only experiment mode; its output does not advance the pipeline (the
Scenario Generator's native contract rejects ungrounded extractions).

## Review flow (no live waiting process)

1. A stage that needs review returns exit 2 and writes
   `reviews/<kind>.request.json` (question, material with hashes, summary).
2. Present the request to the user (the agent's job — see SKILL.md).
3. Record the answer:
   `asago-runner respond <request> --decision <d> --actor <who> ...`
   or write the response file directly (schema in `reviews.py`).
4. Re-run the stage with `--response <file>` to record the decision with
   hash bindings. Material change invalidates the binding; verify-run
   flags stale approvals.

A `profile-required` request is written (not a gate) when the Scenario
Generator's projection aborts because the inferred profile lacks Stage-2
architecture evidence: it names the missing resource categories and how to
supply a reviewed profile for a new run.

For the policy-conflict review, `--decision` is one of `no-conflict`,
`precedence-unchanged-input` (context only; the mapper applies nothing),
or `reconcile` with `--reconciliation-file` holding verbatim span
selections:

```yaml
- parsed_text: derived/parsed/a.parsed.md
  purpose: "customer data rule takes precedence"
  keep_spans: [[0, 234], [512, 700]]
```

## Run directory layout

```
run/
  run.json               identities, config snapshot, stage/attempt records
  inventory.json         flat SHA-256 inventory of retained files
  decisions.jsonl        append-only decision journal
  originals/             policies, system context, SSSOM, run config
  derived/               parse receipts, parsed text, reconciled inputs,
                         span maps, risk-selection adaptations
  reviews/               requests + responses with hash bindings
  preflight/             readiness report incl. Nexus verification
  stages/<stage>/<attempt>/   native outputs, dispatch/attempt records
  reports/               summary.json, index.html
```

A `run.lock` file excludes concurrent writers while a command holds the
run. Attempts are append-only: interrupted work leaves valid partial
evidence and a fresh attempt never overwrites it.

## Independent (non-agent) use

The runner is a plain CLI. A headless caller can drive the same flow: run
the stage commands, parse the final JSON line and exit code, write response
files. No harness-specific API is required. Only one harness (Claude Code)
has been demonstrated; do not claim others as tested.

## Programmatic use from Python

Two supported patterns, both without any agent:

**Pattern 1 — drive the CLI from Python (recommended for full runs).** The
CLI is the orchestration layer (gate sequencing, flow-state transitions),
so invoking it and parsing the final JSON line gives you identical
behaviour to the skill:

```python
import json, subprocess

def stage(*args):
    proc = subprocess.run([".venv/bin/asago-runner", *args],
                          capture_output=True, text=True)
    return proc.returncode, json.loads(proc.stdout.strip().splitlines()[-1])

code, outcome = stage("status", "runs/<your-run>")
```

**Pattern 2 — import the package directly (for analysis and custom
flows).** Every module is importable and the test suite drives them this
way. `RunDir` paths stored in `run.json` are run-relative — resolve them
against `run.path`:

```python
import json, yaml
from pathlib import Path
from asago_runner.config import RunConfig
from asago_runner.evidence import RunDir
from asago_runner.replay import derive_transport
from asago_runner.reporting import build_summary
from asago_runner.verify import verify_run

run = RunDir("runs/<your-run>")
cfg = RunConfig.load(run.path / "originals" / "run-config.yaml",
                     path_map=run.manifest().get("originals_map"))
receipts = json.loads((run.path / run.manifest()["flow"]
                       ["scenario_handoff"]["receipts"]).read_text())
eligibility = derive_transport(yaml.safe_load(Path(receipts[0]["yaml"]).read_text()))
summary = build_summary(run)          # reports/summary.json as a dict
report = verify_run(run, cfg)         # model-free verification
```

Useful entry points: `evidence.RunDir` (manifest, journal, inventory,
locking), `config.RunConfig` (sanitized snapshots, data-flow tables),
`preflight.run_preflight`, `intake.parse_receipts` /
`intake.build_reconciled_input`, `adapters.mapper.run_mapper`,
`adapters.scenarios.*`, `adapters.artifacts.*`, `replay.derive_transport`
and `replay.build_replay_entry`, `adapters.garak_eval.evaluate_entry`,
`reporting.build_summary` / `render_html`, `verify.verify_run`.

**Scope note:** stage orchestration (which stage runs next, review-gate
handling) lives in the CLI command layer. A first-class in-process Python
API for whole-run orchestration is a deliberate Phase 2 item (headless
integration); Pattern 1 covers that need today with identical semantics.
