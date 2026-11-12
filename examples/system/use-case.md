# Use case: ExampleCorp Support Assistant (SYNTHETIC EXAMPLE)

> **Label: synthetic example.** Fabricated system context for the Asago
> skill's labelled initial example. It describes no real system.

## System purpose

The ExampleCorp Support Assistant is a conversational AI customer-service
agent embedded in the ExampleCorp mobile app and website. It answers
customer questions about their own orders, payments and returns, processes
refund requests the customer explicitly makes, and escalates to a human
agent when it cannot resolve a request. The customer is authenticated before
the conversation starts, and the assistant operates with that customer's
order and payment context.

## Legitimate tasks

- Answer questions about the authenticated customer's own orders, payment
  schedules and the public returns policy.
- Process a refund the customer explicitly requests, within the published
  refund limits.
- Offer escalation to a human support agent.

## Architecture and entry points

- **Chat interface (customer-facing).** The customer types messages into the
  app or web chat. This is the primary interface and is directly controlled
  by the customer.
- **Knowledge retrieval (RAG).** Before answering, the assistant retrieves
  passages from a support-article knowledge base. The articles are written
  and maintained by the support-content team; customers cannot directly edit
  them, but the assistant cannot verify authorship of the text it retrieves.
- **Order and payment tools.** Backend APIs to look up orders, schedule
  payments and process refunds. These run with a service account and act on
  the authenticated customer's data only.

## Data and trust boundaries

Customer chat input crosses from an untrusted zone into the assistant's
reasoning. Retrieved knowledge passages and tool results also flow into the
same reasoning context. The backend order and payment services sit behind a
service boundary with the assistant's service account.

## Observable expected behaviour

The assistant is expected to refuse policy-violating requests, to ground
answers in retrieved support content, to take only tool actions the
authenticated customer explicitly requested, and to escalate when it cannot
resolve a request. The assessed boundary is its OpenAI-compatible Chat
Completions endpoint; internal components behind that endpoint are not
individually observed by this assessment.
