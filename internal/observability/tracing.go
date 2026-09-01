package observability

import (
	"context"
	"errors"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/trace"
)

type TraceConfig struct {
	Endpoint string
	Insecure bool
	Service  string
	Version  string
}

func StartOperation(ctx context.Context, kind, id string) (context.Context, trace.Span) {
	return otel.Tracer("github.com/GhaziBenDahmane/Orka/worker").Start(ctx, "job "+kind,
		trace.WithAttributes(attribute.String("job.kind", kind), attribute.String("job.id", id)))
}

func EndOperation(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	} else {
		span.SetStatus(codes.Ok, "")
	}
	span.End()
}

// InitTracing configures W3C trace propagation even when exporting is disabled.
// When an endpoint is provided, spans are batched and exported over OTLP/gRPC.
func InitTracing(ctx context.Context, cfg TraceConfig) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return func(context.Context) error { return nil }, nil
	}
	options := []otlptracegrpc.Option{otlptracegrpc.WithEndpointURL(cfg.Endpoint)}
	if cfg.Insecure {
		options = append(options, otlptracegrpc.WithInsecure())
	}
	exporter, err := otlptracegrpc.New(ctx, options...)
	if err != nil {
		return nil, err
	}
	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(cfg.Service),
		attribute.String("service.version", cfg.Version),
	))
	if err != nil {
		return nil, err
	}
	provider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter), sdktrace.WithResource(res))
	otel.SetTracerProvider(provider)
	return func(shutdownCtx context.Context) error {
		return errors.Join(provider.ForceFlush(shutdownCtx), provider.Shutdown(shutdownCtx))
	}, nil
}
