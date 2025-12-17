package connections

// IdsecConnectionType represents the type of connection.
type IdsecConnectionType string

// IdsecConnectionType values.
const (
	SSH   IdsecConnectionType = "SSH"
	WinRM IdsecConnectionType = "WinRM"
)

// IdsecConnectionDetails represents the details of a connection.
type IdsecConnectionDetails struct {
	Address           string                      `json:"address" mapstructure:"address"`
	Port              int                         `json:"port" mapstructure:"port"`
	ConnectionType    IdsecConnectionType         `json:"connection_type" mapstructure:"connection_type"`
	Credentials       *IdsecConnectionCredentials `json:"credentials" mapstructure:"credentials"`
	ConnectionData    interface{}                 `json:"connection_data" mapstructure:"connection_data"`
	ConnectionRetries int                         `json:"connection_retries" mapstructure:"connection_retries"`
	RetryTickPeriod   int                         `json:"retry_tick_period" mapstructure:"retry_tick_period"`
}
