package metrics

// noopCounter is a counter that does nothing.
type noopCounter struct{}

func (noopCounter) Inc()        {}
func (noopCounter) Add(float64) {}

// noopHistogram is a histogram that does nothing.
type noopHistogram struct{}

func (noopHistogram) Observe(float64) {}

// NoopFactory creates no-op metric instances.
type NoopFactory struct{}

// Counter returns a no-op counter.
func (NoopFactory) Counter(string) Counter { return noopCounter{} }

// Histogram returns a no-op histogram.
func (NoopFactory) Histogram(string) Histogram { return noopHistogram{} }

// NewNoopCollector creates a Collector with no-op metrics.
func NewNoopCollector() *Collector {
	return NewCollector(NoopFactory{})
}
