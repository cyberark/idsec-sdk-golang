package models

// IdsecSIADBBaseExecution defines the base structure for database execution parameters
type IdsecSIADBBaseExecution struct {
	TargetAddress  string `json:"target_address" mapstructure:"target_address" flag:"target-address" desc:"The target address of the connection."`
	TargetUsername string `json:"target_username,omitempty" mapstructure:"target_username,omitempty" flag:"target-username" desc:"The target username account to use to connect."`
	NetworkName    string `json:"network_name,omitempty" mapstructure:"network_name,omitempty" flag:"network-name" desc:"The network name to use for the connection, if applicable."`
}
