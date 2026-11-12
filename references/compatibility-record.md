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

No Asago source repository is modified. No fork branches are tracked; only
immutable commits. The reference demo (`MuneezaAzmat/asago-examples`
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
- Scenario Generator requests have a 300 s application deadline (runner
  passes the stage deadline capped at 300 s); SDK implicit retries are
  disabled by that component.
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
- Runner concurrency one; bounded stage deadlines; deterministic selection
  before target evaluation (never select/retry toward a preferred verdict).
