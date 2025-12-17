package connections

// IdsecConnectionResult represents the result of a connection attempt.
type IdsecConnectionResult struct {
	Stdout string `json:"stdout" mapstructure:"stdout"`
	Stderr string `json:"stderr" mapstructure:"stderr"`
	RC     int    `json:"rc" mapstructure:"rc"`
}
