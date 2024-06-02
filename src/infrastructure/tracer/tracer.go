package tracer

import (
	"context"
	"fmt"

	"github.com/gnaivex/tools/log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/trace"

	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
)

//go:generate mockgen -source=tracer.go -destination=tracer_mock.go -package=tracer Tracer

type Tracer interface {
	Start(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span)
}

func New(ctx context.Context, url, service string) (trace.Tracer, error) {
	// Create the Jaeger exporter.
	exp, err := jaeger.New(
		jaeger.WithCollectorEndpoint(
			jaeger.WithEndpoint(url),
		),
	)
	if err != nil {
		log.ErrorCtx(ctx, "tracer: init new exporter", log.Err(err))

		return nil, fmt.Errorf("tracer: init new exporter: %s", err)
	}

	tp := tracesdk.NewTracerProvider(
		// Always be sure to batch in production.
		tracesdk.WithBatcher(exp),
		// Record information about this application in a Resource.
		tracesdk.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(service),
			semconv.ServiceNamespaceKey.String("connect"),
		)),
	)

	// Registers `tp` as the global trace provider.
	otel.SetTracerProvider(tp)

	// Sets propagator.
	// We must initialize propagator to make it possible
	// to use Extract/Inject methods in gRPC tracing middleware.
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		),
	)

	return tp.Tracer(service), nil
}
