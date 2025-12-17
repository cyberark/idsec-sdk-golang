package connections

// IdsecConnectionCommand represents a command to be executed on a remote server.
type IdsecConnectionCommand struct {
	Command          string                 `json:"command" mapstructure:"command"`                       // The command to actually run
	ExpectedRC       int                    `json:"expected_rc" mapstructure:"expected_rc"`               // Expected return code
	IgnoreRC         bool                   `json:"ignore_rc" mapstructure:"ignore_rc" default:"false"`   // Whether to ignore the return code
	ExtraCommandData map[string]interface{} `json:"extra_command_data" mapstructure:"extra_command_data"` // Extra data for the command
	RetryCount       int                    `json:"retry_count" mapstructure:"retry_count" default:"3"`   // Number of times to retry the command if it fails
	RetryDelay       int                    `json:"retry_delay" mapstructure:"retry_delay" default:"5"`   // Delay in seconds between retries
	RetryOnErrors    []string               `json:"retry_on_errors" mapstructure:"retry_on_errors"`       // List of error messages to retry on
}
