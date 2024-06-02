// Code generated by MockGen. DO NOT EDIT.
// Source: tracer.go

// Package tracer is a generated GoMock package.
package tracer

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	trace "go.opentelemetry.io/otel/trace"
)

// MockTracer is a mock of Tracer interface.
type MockTracer struct {
	ctrl     *gomock.Controller
	recorder *MockTracerMockRecorder
}

// MockTracerMockRecorder is the mock recorder for MockTracer.
type MockTracerMockRecorder struct {
	mock *MockTracer
}

// NewMockTracer creates a new mock instance.
func NewMockTracer(ctrl *gomock.Controller) *MockTracer {
	mock := &MockTracer{ctrl: ctrl}
	mock.recorder = &MockTracerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTracer) EXPECT() *MockTracerMockRecorder {
	return m.recorder
}

// Start mocks base method.
func (m *MockTracer) Start(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, spanName}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Start", varargs...)
	ret0, _ := ret[0].(context.Context)
	ret1, _ := ret[1].(trace.Span)
	return ret0, ret1
}

// Start indicates an expected call of Start.
func (mr *MockTracerMockRecorder) Start(ctx, spanName interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, spanName}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockTracer)(nil).Start), varargs...)
}