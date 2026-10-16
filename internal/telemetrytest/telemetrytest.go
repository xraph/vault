// Package telemetrytest records what vault's telemetry emits so tests can
// assert on it: spans through a tracetest.SpanRecorder installed as the
// global tracer provider, and metrics through a go-utils sink that remembers
// every series it handed out.
package telemetrytest

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"

	gometrics "github.com/xraph/go-utils/metrics"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// Spans installs a span recorder as the global tracer provider for the rest
// of the test and puts the old provider back in cleanup.
func Spans(t testing.TB) *tracetest.SpanRecorder {
	t.Helper()
	prev := otel.GetTracerProvider()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		// t.Context() is already cancelled when cleanup runs.
		if err := tp.Shutdown(context.Background()); err != nil {
			t.Errorf("shut down the test tracer provider: %v", err)
		}
	})
	return rec
}

// Named returns the ended spans called name, in the order they ended.
func Named(rec *tracetest.SpanRecorder, name string) []sdktrace.ReadOnlySpan {
	var out []sdktrace.ReadOnlySpan
	for _, s := range rec.Ended() {
		if s.Name() == name {
			out = append(out, s)
		}
	}
	return out
}

// Attr returns the value of the attribute key on s as a string, and whether
// s has it.
func Attr(s sdktrace.ReadOnlySpan, key string) (string, bool) {
	for _, kv := range s.Attributes() {
		if string(kv.Key) == key {
			return kv.Value.String(), true
		}
	}
	return "", false
}

// AssertNoLeak fails the test if any needle appears anywhere on an ended
// span: its name, an attribute, an event or event attribute, its status
// description, or a link's attributes.
func AssertNoLeak(t testing.TB, rec *tracetest.SpanRecorder, needles ...string) {
	t.Helper()
	for _, s := range rec.Ended() {
		texts := []string{s.Name(), s.Status().Description}
		for _, kv := range s.Attributes() {
			texts = append(texts, string(kv.Key), kv.Value.String())
		}
		for _, ev := range s.Events() {
			texts = append(texts, ev.Name)
			for _, kv := range ev.Attributes {
				texts = append(texts, string(kv.Key), kv.Value.String())
			}
		}
		for _, l := range s.Links() {
			for _, kv := range l.Attributes {
				texts = append(texts, string(kv.Key), kv.Value.String())
			}
		}
		for _, text := range texts {
			for _, needle := range needles {
				if strings.Contains(text, needle) {
					t.Errorf("span %q carries %q in %q", s.Name(), needle, text)
				}
			}
		}
	}
}

// Sink is a go-utils metrics sink that keeps every counter and histogram it
// hands out, keyed by name and labels.
type Sink struct {
	*gometrics.MockMetrics

	mu         sync.Mutex
	counters   map[string]*gometrics.MockCounter
	histograms map[string]*gometrics.MockHistogram
	labels     map[string][]map[string]string // name -> label sets handed out
}

// NewSink returns an empty sink.
func NewSink() *Sink {
	s := &Sink{
		MockMetrics: gometrics.NewMockMetrics(),
		counters:    make(map[string]*gometrics.MockCounter),
		histograms:  make(map[string]*gometrics.MockHistogram),
		labels:      make(map[string][]map[string]string),
	}
	s.CounterFunc = func(name string, opts ...gometrics.MetricOption) gometrics.Counter {
		s.mu.Lock()
		defer s.mu.Unlock()
		k := s.key(name, opts)
		c, ok := s.counters[k]
		if !ok {
			c = gometrics.NewMockCounter()
			s.counters[k] = c
		}
		return c
	}
	s.HistogramFunc = func(name string, opts ...gometrics.MetricOption) gometrics.Histogram {
		s.mu.Lock()
		defer s.mu.Unlock()
		k := s.key(name, opts)
		h, ok := s.histograms[k]
		if !ok {
			h = gometrics.NewMockHistogram()
			s.histograms[k] = h
		}
		return h
	}
	return s
}

// key builds the series key for name and the labels in opts, and remembers
// the label set the first time it sees it. The caller holds s.mu.
func (s *Sink) key(name string, opts []gometrics.MetricOption) string {
	var o gometrics.MetricOptions
	for _, opt := range opts {
		opt(&o)
	}
	k := SeriesKey(name, o.Labels)
	if _, seen := s.counters[k]; !seen {
		if _, seen := s.histograms[k]; !seen {
			s.labels[name] = append(s.labels[name], maps.Clone(o.Labels))
		}
	}
	return k
}

// SeriesKey renders name and labels the way the sink keys a series:
// name{k1="v1",k2="v2"} with the keys sorted.
func SeriesKey(name string, labels map[string]string) string {
	keys := slices.Sorted(maps.Keys(labels))
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%q", k, labels[k]))
	}
	return name + "{" + strings.Join(parts, ",") + "}"
}

// Count returns a counter's value, 0 when the series was never created.
func (s *Sink) Count(name string, labels map[string]string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.counters[SeriesKey(name, labels)]; ok {
		return c.Value()
	}
	return 0
}

// Observations returns how many values a histogram series recorded.
func (s *Sink) Observations(name string, labels map[string]string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h, ok := s.histograms[SeriesKey(name, labels)]; ok {
		return h.Count()
	}
	return 0
}

// LabelSets returns every label set handed out under name.
func (s *Sink) LabelSets(name string) []map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.labels[name])
}

// Names returns every metric name the sink handed a series out for.
func (s *Sink) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Sorted(maps.Keys(s.labels))
}

// AssertNoLeak fails the test if any needle appears in a metric name, label
// key or label value the sink handed out.
func (s *Sink) AssertNoLeak(t testing.TB, needles ...string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, sets := range s.labels {
		for _, set := range sets {
			text := SeriesKey(name, set)
			for _, needle := range needles {
				if strings.Contains(text, needle) {
					t.Errorf("metric series %s carries %q", text, needle)
				}
			}
		}
	}
}
