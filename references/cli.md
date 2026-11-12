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
asago-runner new-run --config <cfg.yaml> [--run-dir DIR] [--cache-dir DIR]
asago-runner preflight  RUN [--response FILE] [--cache-dir DIR] [--garak-env DIR]
asago-runner intake     RUN [--response FILE]
asago-runner map        RUN [--no-llm]
asago-runner scenarios  RUN
asago-runner artifacts  RUN
asago-runner replay-review RUN [--response FILE]
asago-runner evaluate   RUN [--garak-env DIR]
asago-runner report     RUN
asago-runner verify-run RUN
asago-runner status     RUN
asago-runner respond    REQUEST --decision D [--actor A] [--notes N]
                        [--clarification TEXT] [--reconciliation-file FILE]
```

`RUN` is the run directory created by `new-run`. The pipeline order is the
command order; each stage refuses to run before its prerequisites are
recorded (with actionable blockers). `--no-llm` on `map` is the model-free
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
