# Compatibility record

Exact commits, packages, environments, schema versions, supported surface
and known limitations for the Phase 1 runner. Pins record the tested
combination; the plan's section 9 anchors are the research starting points.

## Environments

| Environment | Contents | Lock |
| --- | --- | --- |
| runner (`.venv`, Python 3.13.7) | `asago-runner` + the three Asago components + OTel SDK | `uv.lock` |
| `garak-env/` (Python 3.13.7) | pinned Garak fork | `garak-env/uv.lock` |

Two locked environments: the Garak fork and the Policy Mapper have disjoint
version constraints (e.g. numpy, transformers), and the reference demo also
separates Garak. The environments exchange files only. Consolidation is
optional later.

## Component pins (all immutable commits)

| Component | Commit | Version | Status at adoption |
| --- | --- | --- | --- |
| asago-policy-mapper | `630c77c5f82938f1180fc313324e718c379f2abf` | 0.1.0 | upstream `main` commit (merge of PR #143) |
| asago-scenario-generator | `98fba15de8162c8d064ebff1d381d13a62f49807` | 0.1.0 | upstream `main` commit (merge of PR #43) |
| asago-artifact-generator | `8f481944fd7abd72cd131c14ee9ab366d8d98372` | 0.1.0 | upstream `main` commit (merge of PR #7); **PR #8 (`a7c586b7…`) NOT adopted** — structural validation only, recorded human fidelity assessment |
| garak (trustyai-explainability fork) | `06aba1a2c9b142d561eeeff08dfaffcbe77487c3` | 0.15.0.post1.dev2+rhaiv.5 | PR #11 head, **open/unmerged** when adopted; supplies `probes.injection.IndirectInjection` and `detectors.injection_judge.InjectionJudge` |
| ai-atlas-nexus | `c7a53040c45761376993386b0416a2b977591426` | 1.2.5 | pinned via `tool.uv.override-dependencies` because the mapper declares floating `@main`; this is the commit the pinned mapper revision's own `uv.lock` validated |
| report theme mapping | `d2423c7bf12432f44fab6963f497dc7f975c7c26` (asago-policy-mapper PR #79 head; **open/unmerged** when adopted) | report navigation v1 | The runner vendors only `data/report_themes.yaml` (curated theme labels and category→theme links) for the offline report's theme grouping; it joins through the run's own retained SSSOM mapping (resolved from `sssom.path` via the config snapshot and `originals_map`, with its path and hash shown), not a hardcoded filename. No mapper source is modified or monkeypatched. SHA-256 `0d49cb179e8f067c4826dde7070891dceef56c6f95c5e8e69b964d537badc240`. |

No Asago source repository is modified. No fork branches are tracked; only
immutable commits. The reference demo (`asago-ai/asago-examples`
`6fcb6ad6…`) was read for integration patterns but none of its runtime
monkeypatching (generator wrapping, prompt patches) is used — see
"Deviations from the reference demo".

## Verified integration facts (E-experiments)

| Experiment | Result |
| --- | --- |
| **E1** environment resolution | Both environments resolve and install; `direct_url.json` reports every component at its pinned commit; all CLIs invoke. The runner root needed `tool.hatch.metadata.allow-direct-references = true` for git pins. |
| **E2** no-LLM mapper run | `asago-policy-mapper extract --no-query-gen --no-judge --no-grounding --no-causal-synthesis --no-expand-siblings` runs model-free (no LLM env passed, `llm_calls: 0`) with local retrieval models. 21 risks matched on the synthetic example policy (5 `ibm-risk-atlas`), agentic filter applied (native log: "Filtered 32 agentic risks"). |
| **E3** scenario handoff shapes | The Artifact Generator's `load_scenario` consumes the scenario-generator YAML shape; `lookup_surface` confirmed to fall back to `user_turn` on unknown zones (source-read) — the runner's eligibility check runs **before** generation to prevent the indirect-to-direct downgrade. The Scenario Generator's `RiskCard` **rejects** `grounding_confidence: "ungrounded"` (IR-only mapper output) — only the grounded live mapper path advances the pipeline (runner-enforced gate). |
| **E4** Garak failure matrix | Stub-server tests (7/7 passing): working pair → verdict; judge HTTP 400 → process crash (native `[None].text` dereference) mapped to `inconclusive/evaluator-crashed` with receipts retained; malformed judgment → inconclusive; hanging target → parent deadline → `inconclusive/deadline-exceeded`; target 500 → internal retries then inconclusive; no secret leakage into evidence. |
| **E6** Nexus pairing | Sparse fetch (54 YAML files) at the exact commit; installed-package data matches fetched bytes; native loader: 630 risks with base dir == 630 package-only; 560 after the mapper CLI's exclusions. Tampering with one cached file is detected and blocks; restoring re-verifies. |

E5 (labelled real transport smoke against the chosen endpoint) runs only
when the live replay requires declared-tools/prior-tool-message support —
at the input-readiness review for the concrete run.

## Contract notes discovered during integration

- **Nexus data loading** merges `base_dir` YAMLs with the installed
  package's bundled data **by entity id** (idempotent), so the sparse
  `src/ai_atlas_nexus/data` cache is complete for both the loader and the
  mapper's mitigation enrichment (which reads
  `knowledge_graph/{nist_ai_rmf_actions_data,aiuc1_data}.yaml` and
  `knowledge_graph/mappings/*.yaml`).
- **Entry-point zones**: at the pinned scenario-generator revision the
  narrative entry point is the reviewed profile name (no legacy
  parenthetical suffix); zones live in structured projection data. The
  runner derives transport from those structured facts and supplies the
  legacy suffix through a recorded, provenance-backed adaptation when
  needed. The artifact generator's own classifier still defaults unknown
  suffixes to `user_turn` — which is why eligibility runs before
  generation.
- **SSSOM**: the mapper's pinned `risk_to_category.sssom.tsv` (copied to
  `examples/mappings/`) maps IBM risk IDs to OWASP LLM categories and loads
  through the scenario generator's native `load_sssom`. Scenario
  Generator's `attack-patterns*.sssom.tsv` files are a different mapping
  set and are not interchangeable.
- **Garak report shape**: attempt rows live in `garak.report.jsonl`
  (`entry_type: attempt`); detector results under
  `detector_results["injection_judge.InjectionJudge"]`; judge confidences
  under `notes.injection_judge_scores`. The generator does not retain
  `response.model` — returned model IDs remain unknown.

## Live-run model contracts (configured gateway)

The live smoke run uses an OpenAI-compatible model gateway. The tested
model identifiers and gateway hostnames are deliberately omitted from this
public record; they remain in the run evidence and decision journal. The
contracts discovered through labelled smoke checks and live attempts are
recorded here by behaviour:

- **Legacy token/temperature parameters are not universal**: one gateway
  model rejects `max_tokens` (requiring `max_completion_tokens`) and any
  `temperature` other than 1. The mapper (`--output-token-parameter`,
  `--temperature`) and the Garak driver
  (`ASAGO_GARAK_TOKEN_PARAM`/`ASAGO_GARAK_TEMPERATURE` with
  `suppressed_params`/`extra_params`) are configured accordingly.
- **Strict schema validators reject the scenario schemas**: the generator's
  structured-output schemas use JSON Schema keywords (`maxProperties`) that
  an OpenAI-strict `json_schema` validator rejects
  (`BadRequestError 400: Invalid schema … 'maxProperties'`). The reference
  demo works around this by patching the schema at runtime — forbidden
  here. Resolution: the scenario role uses a model whose validator accepts
  the native schemas unchanged. No source edits, no monkeypatching.
- **A reasoning-heavy model can exceed the component's hardcoded caps**:
  one tested model accepted every request shape (all temperatures, both
  token parameters, strict `json_schema` with `maxProperties`,
  tools/prior-tool-message replay), but its structured drafts for the
  scenario generator's semantic stages exceeded that component's
  **hardcoded per-call completion caps** (`actor_profile`/`behavior_spec`/
  filter 4096, `narrative`/`attack_tree` 8192;
  `min(operation_cap, transport_cap)` — an operator transport cap can only
  lower them). Two full attempts quarantined 10/10 candidates with
  `CompletionLengthError`. That model also ran the mapper several times
  slower than a fast gateway model and exceeded a 3600 s stage deadline
  near completion.
- **Inferred-only scenario runs can abort projection**: without a reviewed
  `system.profile_file`, the Scenario Generator's Stage-1 inference
  produces an `inferred_partial` profile that cannot supply Stage-2
  inventory evidence (`external_integrations`, `trust_boundaries`). If the
  selected risks require those categories, native projection readiness
  aborts with exit 1 *after* the mapper has run. The runner turns that
  specific abort into a `needs-review` outcome with the missing categories
  and a `profile-required` request (not a bare failure); preflight warns
  beforehand. Supply a reviewed profile to avoid the wasted mapper spend.
- **Scenario role resolution (recorded deviation)**: with the
  reasoning-heavy model length-incompatible, several fast/compact models
  schema-rejected (OpenAI-strict `maxProperties`), and Gemini-family models
  schema-rejected (Google path `INVALID_ARGUMENT` on the behavior-draft
  schema — the reference demo needed runtime schema surgery for Gemini,
  which is forbidden here), the scenario role runs on a compact gateway
  model that accepts the exact `BehaviorDraftV2For9Handles` schema
  (verified by labelled schema replay) and produces concise drafts (296
  completion tokens on the minimal probe vs the 4096 cap). Flagged for
  user review on return.
- **Artifact generator**: hardcodes `temperature=0.2` upstream with no
  configuration; some gateway models reject non-default temperature. The
  artifact role therefore uses a model that accepts it.
- **A public GPT-4o-class model**: accepted `json_schema` structured
  output, declared `tools`, prior `assistant.tool_calls` and `role=tool`
  messages in the labelled transport smoke checks (E5-adjacent; evidence
  retained with the run).

The target and judge shared one model per the user's smoke-run choice —
recorded in every summary as a lack of independent validation.

## Deviations from the reference demo

The demo (`asago-demo`) was consulted, not adopted. Specifically **not**
used: its in-process monkeypatching of Garak generators (timeout/
BadRequestError wrappers — the runner instead maps crashes to inconclusive
with parent-enforced deadlines); its `unittest.mock` patches of the
scenario generator's prompts/schema; its `amount → number` tool-schema
special case (name-based type inference is forbidden here); its saved
FS-ISAC extraction starting point (the live run must start from policy
documents). Adopted patterns: conversation entry construction
(transport-only field copy), judge-description composition, outcome
summarization from native attempt rows, config-root plugin wiring
(reimplemented in the `garak-env` driver with env-only secrets).

## Known limitations (disclosed, not hidden)

- Garak/SDK internal retries are not individually bounded (backoff caps
  per-wait intervals; no visible total). The runner adds no replay of its
  own; the parent deadline bounds wall-clock only and does not cancel
  requests already accepted by the endpoint.
- A judge HTTP 400 crashes the native detector; the runner records
  `inconclusive/evaluator-crashed` and retains receipts.
- The mapper and Artifact Generator expose no per-request timeout/retry
  configuration through their public interfaces; model-call evidence is
  "as captured by the component" (`llm_calls` written at completion — a
  crash loses it and the runner says so).
- Scenario Generator requests have a 300 s application deadline (the runner
  passes its own stage deadline capped at 300 s, or 300 s when no stage
  deadline is configured); SDK implicit retries are disabled by that
  component.
- The mapper's annotation view covers only the first document; the HTML
  overview links evidence for all inputs and states that limitation.
- Structural validation of artifacts does not establish semantic fidelity
  (PR #8 not adopted); recorded human assessment covers fidelity.
- `verify-run` establishes recorded consistency, not provider identity,
  hidden HTTP retries or attestation truth.

## Phase 1 scope decisions

- Taxonomy/risk scenario workflow only (no STPA).
- Direct chat user-turn attack is the faithfully-labelled first live
  surface; tool-return live coverage is conditional on a reviewed carrier
  and endpoint support (offline adapter path is tested).
- No OSCAL export (Phase 2). Evidence retains what OSCAL will need.
- Runner concurrency one; optional stage deadlines (default none — a stage
  runs until the component finishes); deterministic selection
  before target evaluation (never select/retry toward a preferred verdict).
