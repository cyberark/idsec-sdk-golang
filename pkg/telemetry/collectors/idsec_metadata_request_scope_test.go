package collectors

import (
	"fmt"
	"sync"
	"testing"
)

// TestCollectMetricsForRequestReportsOnlyItsOwnRequest asserts that concurrent
// collections do not report each other's request.
//
// This is the defect the request metadata was moved off the collector to fix. A
// single client sends requests from as many goroutines as its caller cares to
// use, and the SDK's own fan-out helpers do exactly that. While the route and
// operation were stored on the collector, the last writer won: a request could
// be reported under a route it never asked for, and the concurrent map writes
// were a race that could crash the process outright.
//
// Run with -race to see the unsynchronised writes as well as the wrong values.
func TestCollectMetricsForRequestReportsOnlyItsOwnRequest(t *testing.T) {
	t.Parallel()

	collector := &IdsecMetadataMetricsCollector{}

	const requests = 64
	var waitGroup sync.WaitGroup
	failures := make(chan string, requests)

	for requestIndex := range requests {
		waitGroup.Add(1)
		go func(requestIndex int) {
			defer waitGroup.Done()

			request := IdsecRequestMetadata{
				Route:     fmt.Sprintf("/route/%d", requestIndex),
				Service:   fmt.Sprintf("service-%d", requestIndex),
				Class:     fmt.Sprintf("Class%d", requestIndex),
				Operation: fmt.Sprintf("Operation%d", requestIndex),
			}

			metrics, err := collector.CollectMetricsForRequest(request)
			if err != nil {
				failures <- fmt.Sprintf("request %d: unexpected error: %v", requestIndex, err)
				return
			}

			for name, expected := range map[string]string{
				"route":     request.Route,
				"service":   request.Service,
				"class":     request.Class,
				"operation": request.Operation,
			} {
				metric := findMetricByName(metrics.Metrics, name)
				if metric == nil {
					failures <- fmt.Sprintf("request %d: no %s metric", requestIndex, name)
					continue
				}
				if metric.Value != expected {
					failures <- fmt.Sprintf(
						"request %d reported %s %v, want %s", requestIndex, name, metric.Value, expected)
				}
			}
		}(requestIndex)
	}

	waitGroup.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
}

// TestExtraContextIsSafeUnderConcurrentUse asserts that the tool context can be
// written and read while requests are being collected.
//
// The tool context outlives a request and is still shared, so unlike the
// request metadata it is guarded by a lock rather than moved. Its map was
// previously written with no synchronisation at all, which a concurrent read
// could crash on.
//
// Run with -race.
func TestExtraContextIsSafeUnderConcurrentUse(t *testing.T) {
	t.Parallel()

	collector := &IdsecMetadataMetricsCollector{}

	const goroutines = 32
	var waitGroup sync.WaitGroup

	for index := range goroutines {
		waitGroup.Add(2)
		go func(index int) {
			defer waitGroup.Done()
			collector.AddExtraContextField(
				fmt.Sprintf("field_%d", index), fmt.Sprintf("f%d", index), fmt.Sprintf("value_%d", index))
		}(index)
		go func(index int) {
			defer waitGroup.Done()
			if _, err := collector.CollectMetricsForRequest(
				IdsecRequestMetadata{Route: fmt.Sprintf("/route/%d", index)}); err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			collector.GetExtraContextField(fmt.Sprintf("f%d", index))
		}(index)
	}

	waitGroup.Wait()
}

// TestClearExtraContextIsSafeUnderConcurrentUse asserts that clearing the tool
// context cannot race a collection reading it.
//
// Run with -race.
func TestClearExtraContextIsSafeUnderConcurrentUse(t *testing.T) {
	t.Parallel()

	collector := &IdsecMetadataMetricsCollector{}
	collector.AddExtraContextField("tool", "tl", "test")

	const goroutines = 32
	var waitGroup sync.WaitGroup

	for index := range goroutines {
		waitGroup.Add(2)
		go func() {
			defer waitGroup.Done()
			collector.ClearExtraContext()
		}()
		go func(index int) {
			defer waitGroup.Done()
			if _, err := collector.CollectMetricsForRequest(
				IdsecRequestMetadata{Route: fmt.Sprintf("/route/%d", index)}); err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		}(index)
	}

	waitGroup.Wait()
}
