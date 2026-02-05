package common

import (
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
)

var (
	// DefaultPCloudRetryStrategy defines the default retry strategy for PCloud service
	PCloudDefaultRetryCount = 5
	// PCloudDefaultRetryableErrorCodes defines the default retryable error codes for PCloud service
	PCloudDefaultRetryableErrorCodes = []string{
		"ITADM111E",
		"SRAPIE0006",
	}
	// PCloudDefaultInitialRetryDelay defines the default initial retry delay for PCloud service
	PCloudDefaultInitialRetryDelay = 1 * time.Second
	// PCloudDefaultMaxRetryDelay defines the default maximum retry delay for PCloud service
	PCloudDefaultMaxRetryDelay = 10 * time.Second
	// PCloudDefaultRetryBackoffMultiplier defines the default retry backoff multiplier for PCloud service
	PCloudDefaultRetryBackoffMultiplier = 2.0
	// PCloudDefaultRetryJitterEnabled defines whether jitter is enabled for PCloud service retries
	PCloudDefaultRetryJitterEnabled = true
)

// DefaultPCloudRetryStrategy returns the default retry strategy for PCloud service
// using exponential backoff with jitter for transient errors.
// It retries on specific error codes defined in PCloudDefaultRetryableErrorCodes.
// The strategy uses the default parameters defined above.
// Returns:
//   - common.IdsecClientRetryStrategy: The configured retry strategy.
func DefaultPCloudRetryStrategy() common.IdsecClientRetryStrategy {
	return common.NewRetryWithBackoffStrategy(
		common.NewRetryBodyErrorsStrategy(
			PCloudDefaultRetryCount,
			PCloudDefaultRetryableErrorCodes,
			false,
		),
		PCloudDefaultInitialRetryDelay,
		PCloudDefaultMaxRetryDelay,
		PCloudDefaultRetryBackoffMultiplier,
		PCloudDefaultRetryJitterEnabled,
	)
}
