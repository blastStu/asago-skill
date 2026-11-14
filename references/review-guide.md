# Review guide

Two default review boundaries plus a conditional policy-conflict review.
Reviews are files with hash bindings; grouped presentation is acceptable
when its scope and sampling are explicit. Never claim every item was
individually approved after a summary review, and never infer approval from
elapsed time or stage progression.

## 1. Input readiness (before the pipeline)

The preflight request contains the subject status (built system vs
proposed design — which decides how far the pipeline goes), the data-flow
table (which configured provider receives policies, retrieval text, system
facts, attacks and responses), shared model roles, scope and the material
hashes. Present:

- the policy documents and their purpose;
- the subject status and what it means for scope: a **built** system runs
  the full chain including evaluation; a **proposed design** stops after
  the Scenario Generator with the threat picture (nothing is evaluated —
  there is nothing to attack yet);
- the system identity record (name, boundary, sanitized endpoint identity,
  who confirmed it and when — synthetic/unknown values labelled as such;
  for a proposed design, the intended boundary, plainly labelled as a
  design);
- the data-flow table and ask explicitly: *are these destinations
  acceptable for this material?* A labelled synthetic/public policy is the
  default unless the user has approved destinations for their own material;
- the scope (risk selection, generation limits, target samples, deadlines)
  and the native retry limitations;
- any **advisories** from preflight (the request's `advisories` list). In
  particular, when no capability profile is supplied, say plainly that an
  inferred-only run can abort projection after the mapper has run if the
  risks need `external_integrations`/`trust_boundaries`, and recommend
  supplying a reviewed profile up front;
- anything absent from the policy the user cares about — a supplement is a
  separately preserved draft until the user verifies it.

## 2. Policy conflict (multiple documents only)

Present the parsed documents and ask about suspected disagreements **with
actual passages and locations**. This review is interpretive; say so — it
cannot certify that every conflict was found. Record the visible exchange.
Outcomes:

- **no-conflict** — originals proceed unchanged;
- **precedence-unchanged-input** — precedence recorded as context only;
  state plainly that the mapper applies nothing (it has no precedence
  option);
- **reconcile** — a reconciled effective input is built from **verbatim
  span selections** of the preserved parsed originals, with a span map
  (document hash, parsed-text hash, character ranges, effective ranges,
  decision id) and a model-free verbatim-slice check. Losing passages stay
  in the evidence. Approved rewrites/translations/supplements are separate
  labelled derivations — never silent substitutions.

## 3. Generated test plan (before target evaluation)

The request binds the **exact replay batch Garak will receive**. Present,
per entry: the messages (attack placement and role), the effective
`tools`/`tool_choice` — flagging that derived schemas are adapter-asserted
test assumptions from the artifact's system-turn declarations, **not**
confirmed deployed interfaces — the composed judge criteria and threshold,
the target/judge endpoints and models, shared-model flags, and partial
coverage items with their omitted behavior. Approval covers the full batch;
hashes are rechecked immediately before dispatch, and any change requires
re-review.

## Presenting results

The HTML report embeds unredacted policy text, attacks and model output, and
the page carries that notice. Do not publish or forward it without the
user's explicit decision; describe it as confidential when presenting it.

Lead with stage status and counts using their own denominators (risks
matched → downstream-supported → admitted scenarios → validated artifacts →
usable evaluations; there is no single universal coverage percentage).
Show a representative sample with links to full inventories, meaningful
exceptions (unsupported taxonomies, quarantined scenarios, skipped/partial
coverage, inconclusive evaluations with reasons), and the tested surface.
State what the evidence does not establish: no general compliance or safety
claim, no backend-effect proof from a proposed tool call, and no
independent validation when target and judge share a model.
