---
name: asago-policy-to-garak
description: Orchestrate the Asago policy-to-Garak workflow — take a user's AI policy documents and system context through the real Policy Mapper, Scenario Generator and Artifact Generator to real Garak results against an OpenAI-compatible Chat Completions endpoint, with review gates, durable evidence and an offline HTML overview. Use when the user wants to turn AI policies into adversarial test results, run the Asago pipeline, or assess an AI assistant against its policy.
---

# Asago policy-to-Garak skill

You orchestrate a deterministic Python runner that invokes the real Asago
components. **Never replace component analysis with your own**: no
invented risks, scenarios, artifacts or evaluation results. You help the
user prepare inputs, present reviews, explain progress and link results.

## Ground rules

1. **Run the runner; do not synthesize outputs.** Every stage is
   `asago-runner <command>` from the skill root's `.venv`. Machine-readable
   JSON is printed as the last stdout line; exit codes distinguish
   `0 completed · 4 completed-with-gaps · 2 needs-review · 3 blocked · 1 failed`.
   Never treat an incomplete stage as success.
2. **Keep the states distinct.** A risk match is not a finding; an admitted
   scenario is not an executable artifact; structural validation is not
   coverage; an inconclusive evaluation is not a pass. A proposed tool call
   is not evidence of a completed backend effect.
3. **Make exclusions visible.** Unsupported taxonomies, governance-only
   risks, skipped/partial coverage, quarantined scenarios and inconclusive
   evaluations are reported, never hidden.
4. **Do not modify Asago source.** Input adaptations are allowed only when
   the runner records them with provenance (it does this itself).
5. **Evidence is files; telemetry is OTel.** Audit information lives in the
   run directory and survives without a Collector. Never put policy text,
   attacks or responses on telemetry.
6. **Secrets stay in environment variables.** Never write API keys into
   files, commands you show the user, or your replies.
7. **Speak the user's language.** If their documents are not in English,
   keep originals and prepare any translation as a separately reviewed
   derivation; record material adaptations.

## Setup (once)

```bash
uv sync --locked                       # runner + Asago components (Python 3.13)
uv run --project garak-env --locked sync   # separate pinned Garak environment
```

IBM AI Atlas Nexus data is fetched automatically into a runner-managed cache
at the exact revision resolved for the mapper environment; users never need
their own clone. See `references/setup.md` for details and prerequisites.

## Workflow

The runner enforces two default review boundaries — **input readiness**
before the pipeline and the **generated test plan** before target
evaluation — plus a policy-conflict review when several policy documents are
supplied. Reviews are files: the runner writes a request, you present it,
the user answers, and the answer is recorded with hash bindings. Never infer
approval from elapsed time or stage progression.

### 1. Intake

Gather from the user (see `references/review-guide.md` for the full
checklist and question phrasing):

- **Policy documents** (`.md`, `.txt`, `.pdf`, `.docx`, `.html`, …).
- **System context**: use-case description; capability profile;
  qualification facts; system identity (name, boundary, sanitized endpoint,
  who confirmed it and when — label synthetic examples and unknown values).
- **Model connections** per role (mapper/scenario/artifact generation,
  target, judge) as environment variables named in the run configuration.
  Copy `examples/config.example.yaml`, point it at their documents, and have
  them export the env vars it names. Ask whether concerns are missing from
  the policy; any supplement is a draft the user must verify before use.
- **Run scope**: which risks/surfaces, generation limits, target samples.

Show the user the data-flow table from preflight output: which provider
receives policies, system facts, attacks and responses. Use a labelled
synthetic/public policy unless the user has approved destinations for their
material. A shared target/judge model is acceptable for a smoke run and is
recorded as a lack of independent validation.

### 2. Run the stages

```bash
RUN=runs/<label>
.venv/bin/asago-runner new-run --config <config.yaml> --run-dir $RUN
.venv/bin/asago-runner preflight  $RUN      # → needs-review: input readiness
# present the request; then:
.venv/bin/asago-runner respond $RUN/reviews/input-readiness.request.json \
    --decision approve --actor "<user>" --notes "<visible notes>"
.venv/bin/asago-runner preflight  $RUN --response $RUN/reviews/input-readiness.response.json
.venv/bin/asago-runner intake     $RUN      # parse receipts; conflict review if multi-doc
.venv/bin/asago-runner map        $RUN      # Policy Mapper (real CLI subprocess)
.venv/bin/asago-runner scenarios  $RUN      # projection preflight + generation
.venv/bin/asago-runner artifacts  $RUN      # eligibility + Artifact Generator + replay entries
.venv/bin/asago-runner replay-review $RUN   # → needs-review: generated test plan
# present the replay entries; then respond as above with the test-plan request
.venv/bin/asago-runner evaluate   $RUN      # Garak, one artifact per subprocess
.venv/bin/asago-runner report     $RUN      # summary.json + offline index.html
.venv/bin/asago-runner verify-run $RUN      # model-free consistency verification
```

Notes:

- For multiple policies, `intake` returns a conflict review request. Present
  the parsed documents, ask about suspected disagreements with actual
  passages, and record the user's precedence answer. If precedence changes
  the effective input, build the reconciliation from **verbatim span
  selections** (the runner verifies slices model-free). Never paraphrase.
- `scenarios` may return a qualification-facts review: fill the generated
  facts template with real readings; absent/unknown facts must be resolved
  by the user, not invented.
- Stop at any `blocked` outcome, read the blockers, and fix the underlying
  input. Do not work around validation.

### 3. Presenting reviews

Present grouped summaries with a representative sample and links to the
full inventories (paths are in the request/summary JSON). Bind approval to
the whole batch: say what was sampled versus individually inspected. The
request files contain the exact question, material hashes and the data-flow
table. The test-plan review covers the **exact replay entries** Garak will
receive — messages, derived tool schemas (test assumptions, not confirmed
deployed interfaces), judge criteria, target/judge models, and the native
retry limitations.

### 4. Explaining results

Open `reports/index.html` (offline, escaped content). Walk through stage
status, counts with their separate denominators, evaluations with
confidence and reasoning, and gaps. Be explicit about: the tested surface
(a direct chat user-turn attack is labelled as such — it is not indirect
coverage); shared model roles; inconclusive outcomes and why; what the
evidence does and does not establish. Link the native reports and the
decision journal for anything the user wants to audit.

## Failure and interruption

Stages write attempt records before invoking components, so a crash or
timeout never erases the attempt. Interrupted work leaves valid partial
evidence; a fresh attempt does not overwrite it. If the runner reports a
preflight blocker (for example the pinned Nexus data cannot be fetched or
verified), surface the remediation in the blocker text — do not pick a
different data revision yourself.

## Portability

The runner is a plain CLI: any harness or a headless caller can drive the
same stages with the same files (see `references/cli.md` for the command
contract). This skill has been demonstrated in one harness only; do not
claim untested harness support.

## Scope boundaries

Phase 1 ends at Garak results plus the offline HTML overview. OSCAL export,
richer reconciliation, resume/recovery and broader coverage are Phase 2.
Recommenders, mitigation deployment and compliance claims are out of scope.
Do not claim general policy compliance or system safety from a bounded
adversarial sample.
