"""OpenTelemetry operational telemetry for runs and stages.

Operational telemetry is separate from audit evidence: essential audit
information must survive without the Collector, retained traces or
model-provider logs. Export uses the standard OTLP configuration
(``OTEL_EXPORTER_OTLP_ENDPOINT`` etc.); the user provides the Collector.

Content policy: no prompts, responses, policy text or tool payloads are ever
put on spans. Only run/stage/attempt identifiers, statuses, timings and
bounded counts. Export failure is recorded as a warning and never blocks the
pipeline or turns an incomplete evaluation into success.
"""

from __future__ import annotations

import atexit
import logging
from typing import Any

logger = logging.getLogger(__name__)

_SERVICE_NAME = "asago-runner"
_initialized = False
_tracer = None
_export_note: str | None = None


def _endpoint_configured() -> bool:
    import os

    return bool(os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"))


def init_telemetry(service_name: str | None = None) -> dict[str, Any]:
    """Initialise OTel once; returns a recordable status description."""
    global _initialized, _tracer, _export_note
    if _initialized:
        return {"enabled": _tracer is not None, "note": _export_note}
    _initialized = True
    _export_note = None
    if not _endpoint_configured():
        _export_note = (
            "OTEL_EXPORTER_OTLP_ENDPOINT not set; telemetry disabled "
            "(warning only; evidence is unaffected)"
        )
        return {"enabled": False, "note": _export_note}
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create(
            {"service.name": service_name or _SERVICE_NAME}
        )
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer(_SERVICE_NAME)
        atexit.register(_shutdown)
        return {
            "enabled": True,
            "note": "OTLP http export configured from standard OTEL_* settings",
        }
    except Exception as exc:  # noqa: BLE001 - telemetry must never block work
        _export_note = f"telemetry initialisation failed: {exc}; continuing without"
        logger.warning("asago-runner: %s", _export_note)
        return {"enabled": False, "note": _export_note}


def _shutdown() -> None:
    from opentelemetry import trace

    provider = trace.get_tracer_provider()
    shutdown = getattr(provider, "shutdown", None)
    if shutdown is not None:
        try:
            shutdown()
        except Exception as exc:  # noqa: BLE001
            logger.warning("asago-runner: telemetry shutdown failed: %s", exc)


class stage_span:
    """Context manager emitting one stage/attempt span (no content)."""

    def __init__(
        self,
        run_id: str,
        stage: str,
        attempt_id: str | None = None,
        attributes: dict[str, Any] | None = None,
    ):
        self.run_id = run_id
        self.stage = stage
        self.attempt_id = attempt_id
        self.attributes = attributes or {}
        self._span = None

    def __enter__(self):
        if _tracer is None:
            return self
        self._span = _tracer.start_span(
            f"asago.stage.{self.stage}",
            attributes={
                "asago.run_id": self.run_id,
                "asago.stage": self.stage,
                **({"asago.attempt_id": self.attempt_id} if self.attempt_id else {}),
                **{f"asago.attr.{k}": v for k, v in self.attributes.items()},
            },
        )
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._span is not None:
            if exc is not None:
                from opentelemetry.trace import Status, StatusCode

                self._span.set_status(Status(StatusCode.ERROR))
                self._span.record_exception(exc)
            self._span.end()
        return False

    def set_outcome(self, status: str, counts: dict[str, int] | None = None) -> None:
        if self._span is not None:
            self._span.set_attribute("asago.status", status)
            for key, value in (counts or {}).items():
                self._span.set_attribute(f"asago.count.{key}", value)
