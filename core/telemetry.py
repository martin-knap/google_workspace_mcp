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

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_SERVICE_NAME = "google-workspace-mcp"
_OTLP_PROTOCOL_GRPC = "grpc"
_OTLP_PROTOCOL_HTTP = "http/protobuf"


def _otlp_endpoint_configured() -> bool:
    """True if the user pointed us at an OTLP collector via standard env vars."""
    return bool(
        os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        or os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    )


def _build_span_exporter() -> tuple[Any, str]:
    """Build an OTLP span exporter honoring OTEL_EXPORTER_OTLP[_TRACES]_PROTOCOL.

    Defaults to gRPC per the OpenTelemetry specification. Endpoint, headers and
    TLS are read from the standard env vars by the exporter itself.
    """
    protocol = (
        (
            os.getenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
            or os.getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
            or _OTLP_PROTOCOL_GRPC
        )
        .strip()
        .lower()
    )

    if protocol == _OTLP_PROTOCOL_HTTP:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
    elif protocol == _OTLP_PROTOCOL_GRPC:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
    else:
        raise ValueError("OTLP protocol must be 'grpc' or 'http/protobuf'")
    return OTLPSpanExporter(), protocol


def _build_resource():
    """Build an OTEL resource while supplying a useful fallback service name."""
    from opentelemetry.sdk.resources import Resource

    resource = Resource.create()
    service_name = str(resource.attributes.get("service.name", ""))
    if not service_name or service_name.startswith("unknown_service"):
        resource = resource.merge(Resource({"service.name": DEFAULT_SERVICE_NAME}))
    return resource


def configure_telemetry() -> bool:
    """Configure OpenTelemetry tracing if an OTLP endpoint is set.

    Returns True if a real ``TracerProvider`` was installed, False otherwise
    (no endpoint configured, SDK not installed, provider already configured, or
    setup failed). Safe to call unconditionally at startup.
    """
    if not _otlp_endpoint_configured():
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        logger.warning(
            "An OTLP endpoint is set, but the OpenTelemetry SDK is not installed; "
            "reinstall with the 'otel' extra to enable tracing."
        )
        return False

    # OpenTelemetry permits only one global provider. Leave a provider installed
    # by auto-instrumentation or an embedding application untouched.
    if not isinstance(trace.get_tracer_provider(), trace.ProxyTracerProvider):
        logger.info(
            "OpenTelemetry tracing provider is already configured; leaving it unchanged."
        )
        return False

    try:
        exporter, protocol = _build_span_exporter()
    except ImportError:
        logger.warning(
            "OpenTelemetry OTLP exporter not available; reinstall with the "
            "'otel' extra to enable tracing."
        )
        return False
    except Exception as exc:
        logger.warning("OpenTelemetry tracing configuration is invalid: %s", exc)
        return False

    try:
        resource = _build_resource()
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
    except Exception as exc:
        logger.warning("Failed to configure OpenTelemetry tracing: %s", exc)
        return False

    logger.info(
        "OpenTelemetry tracing enabled (service=%s, protocol=%s)",
        resource.attributes.get("service.name"),
        protocol,
    )
    return True
