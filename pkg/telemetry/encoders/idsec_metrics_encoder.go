package encoders

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/collectors"
)

// IdsecMetricsEncoder is an interface for encoding Idsec metrics into a specific format.
type IdsecMetricsEncoder interface {
	// EncodeMetrics encodes the given IdsecMetrics into a byte slice.
	EncodeMetrics(metrics []*collectors.IdsecMetrics) ([]byte, error)
}
