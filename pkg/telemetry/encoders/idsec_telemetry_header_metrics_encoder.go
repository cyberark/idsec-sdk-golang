package encoders

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/collectors"
)

// IdsecTelemetryHeaderMetricsEncoder encodes Idsec metrics into a format suitable for the X-Cybr-Telemetry header.
// The format is Base64Encode(CollectorShortName.MetricName=MetricValue&CollectorShortName.MetricName=MetricValue&...)
type IdsecTelemetryHeaderMetricsEncoder struct{}

func NewIdsecTelemetryHeaderMetricsEncoder() IdsecMetricsEncoder {
	return &IdsecTelemetryHeaderMetricsEncoder{}
}

func (e *IdsecTelemetryHeaderMetricsEncoder) toString(value interface{}) string {
	if value == nil {
		return ""
	}

	switch v := value.(type) {
	case string:
		return v
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", v)
	case float32, float64:
		return fmt.Sprintf("%v", v)
	case bool:
		return fmt.Sprintf("%t", v)
	default:
		// For complex types like maps, slices, structs, use JSON
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(jsonBytes)
	}
}

// EncodeMetrics encodes the provided Idsec metrics into a Base64-encoded string suitable for the X-Cybr-Telemetry header.
func (e *IdsecTelemetryHeaderMetricsEncoder) EncodeMetrics(metrics []*collectors.IdsecMetrics) ([]byte, error) {
	// The format here is standard CyberArk X-Cybr-Telemetry header
	// Which is
	// Base64Encode(CollectorShortName.MetricName=MetricValue&CollectorShortName.MetricName=MetricValue&...)
	// SN = Service Name
	encodedString := fmt.Sprintf("sn=%s", config.IdsecToolInUse())
	for _, metricGroup := range metrics {
		for _, metric := range metricGroup.Metrics {
			if encodedString != "" {
				encodedString += "&"
			}
			encodedString += metricGroup.ShortName + "." + metric.ShortName + "=" + e.toString(metric.Value)
		}
	}
	encodedBytes := []byte(encodedString)
	base64Encoded := make([]byte, base64.StdEncoding.EncodedLen(len(encodedBytes)))
	base64.StdEncoding.Encode(base64Encoded, encodedBytes)
	return base64Encoded, nil
}
