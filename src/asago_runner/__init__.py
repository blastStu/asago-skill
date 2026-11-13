"""Asago runner: orchestration for the Asago pipeline.

The runner executes the Asago component chain from policy documents to
evaluated results. The current evaluation endpoint is Garak against an
OpenAI-compatible Chat Completions endpoint; the stage architecture is
evaluation-agnostic so later phases can add evaluators.

The runner invokes the real Asago components (Policy Mapper, Scenario
Generator, Artifact Generator) and Garak as isolated subprocesses, retains
native outputs and durable evidence, and keeps operational telemetry separate
from audit evidence. It never replaces component analysis and never edits
upstream source.
"""

__version__ = "0.1.0"

RUNNER_NAME = "asago-runner"

# Stage names, in pipeline order.
STAGES = (
    "intake",
    "policy-mapper",
    "scenario-generator",
    "artifact-generator",
    "garak",
)

# Machine-readable stage outcome statuses.
COMPLETED = "completed"
COMPLETED_WITH_GAPS = "completed_with_gaps"
NEEDS_REVIEW = "needs_review"
BLOCKED = "blocked"
FAILED = "failed"

# Exit codes: an incomplete stage must never look like success.
EXIT_OK = 0
EXIT_FAILED = 1
EXIT_NEEDS_REVIEW = 2
EXIT_BLOCKED = 3
EXIT_COMPLETED_WITH_GAPS = 4

STATUS_EXIT_CODES = {
    COMPLETED: EXIT_OK,
    COMPLETED_WITH_GAPS: EXIT_COMPLETED_WITH_GAPS,
    NEEDS_REVIEW: EXIT_NEEDS_REVIEW,
    BLOCKED: EXIT_BLOCKED,
    FAILED: EXIT_FAILED,
}
