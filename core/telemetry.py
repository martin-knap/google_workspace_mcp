"""Optional OpenTelemetry tracing bootstrap.

FastMCP is already instrumented with OpenTelemetry (see ``fastmcp.telemetry``),
but it links only ``opentelemetry-api``, so every span is a no-op until a
``TracerProvider`` with an exporter is configured. This module wires that
provider from the standard ``OTEL_*`` environment variables so FastMCP's
tool-call spans are exported to an OTLP collector.

It is entirely opt-in: if no OTLP endpoint is configured the function is a
no-op, and if the SDK extra is not installed it logs a hint and returns. Enable
it by installing the ``otel`` extra and setting ``OTEL_EXPORTER_OTLP_ENDPOINT``.
"""

import atexit
import logging
import os

logger = logging.getLogger(__name__)

DEFAULT_SERVICE_NAME = "google-workspace-mcp"


def _otlp_endpoint_configured() -> bool:
    """True if the user pointed us at an OTLP collector via standard env vars."""
    return bool(
        os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        or os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    )


def _build_span_exporter():
    """Build an OTLP span exporter honoring OTEL_EXPORTER_OTLP[_TRACES]_PROTOCOL.

    Defaults to gRPC per the OpenTelemetry specification. Endpoint, headers and
    TLS are read from the standard env vars by the exporter itself.
    """
    protocol = (
        os.getenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
        or os.getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
        or "grpc"
    ).lower()

    if protocol.startswith("http"):
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
    else:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
    return OTLPSpanExporter(), protocol


def configure_telemetry() -> bool:
    """Configure OpenTelemetry tracing if an OTLP endpoint is set.

    Returns True if a real ``TracerProvider`` was installed, False otherwise
    (no endpoint configured, SDK not installed, or setup failed). Safe to call
    unconditionally at startup.
    """
    if not _otlp_endpoint_configured():
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        logger.warning(
            "OTEL_EXPORTER_OTLP_ENDPOINT is set but the OpenTelemetry SDK is not "
            "installed; reinstall with the 'otel' extra to enable tracing."
        )
        return False

    # Respect OTEL_SERVICE_NAME / OTEL_RESOURCE_ATTRIBUTES if provided (Resource
    # reads them via the env detector); otherwise fall back to a sensible name.
    if os.getenv("OTEL_SERVICE_NAME"):
        resource = Resource.create()
    else:
        resource = Resource.create({"service.name": DEFAULT_SERVICE_NAME})

    try:
        exporter, protocol = _build_span_exporter()
    except ImportError:
        logger.warning(
            "OpenTelemetry OTLP exporter not available; reinstall with the "
            "'otel' extra to enable tracing."
        )
        return False

    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    # Flush any buffered spans on interpreter exit.
    atexit.register(provider.shutdown)

    endpoint = os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or os.getenv(
        "OTEL_EXPORTER_OTLP_ENDPOINT"
    )
    logger.info(
        "OpenTelemetry tracing enabled (service=%s, protocol=%s, endpoint=%s)",
        resource.attributes.get("service.name"),
        protocol,
        endpoint,
    )
    return True
