package detectors

// IdsecEnvContext holds information about the environment context.
type IdsecEnvContext struct {
	Provider    string
	Environment string
	Region      string
	AccountID   string
	InstanceID  string
}

// IdsecEnvDetector is an interface for detecting the environment context in which the Idsec tool is running.
type IdsecEnvDetector interface {
	// Detect tries to detect the environment context.
	// It returns the detected IdsecEnvContext and a boolean indicating whether detection was successful.
	Detect() (*IdsecEnvContext, bool)
}
