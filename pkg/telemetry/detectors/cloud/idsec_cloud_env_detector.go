package cloud

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/detectors"
)

type IdsecCloudEnvDetector struct {
	detectors []detectors.IdsecEnvDetector
}

func NewIdsecCloudEnvDetector() detectors.IdsecEnvDetector {
	return &IdsecCloudEnvDetector{
		detectors: []detectors.IdsecEnvDetector{
			NewIdsecAWSCloudEnvDetector(),
			NewIdsecAzureCloudDetector(),
			NewIdsecGCPCloudEnvDetector(),
		},
	}
}

func (m *IdsecCloudEnvDetector) Detect() (*detectors.IdsecEnvContext, bool) {
	for _, d := range m.detectors {
		if ctx, ok := d.Detect(); ok {
			return ctx, true
		}
	}
	return &detectors.IdsecEnvContext{
		Provider:    "on-premise",
		Environment: "on-premise",
		Region:      "unknown",
		AccountID:   "unknown",
		InstanceID:  "unknown",
	}, false
}
