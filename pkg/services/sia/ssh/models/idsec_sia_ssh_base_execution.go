package models

// IdsecSIASSHBaseExecution defines the base structure for SSH execution parameters
// shared by all SSH execution flavors (interactive shell or single command).
type IdsecSIASSHBaseExecution struct {
	TargetAddress  string `json:"target_address" mapstructure:"target_address" flag:"target-address" desc:"The target address of the connection."`
	TargetUsername string `json:"target_username,omitempty" mapstructure:"target_username,omitempty" flag:"target-username" desc:"The target username account to use for the connection."`
	TargetPort     int    `json:"target_port,omitempty" mapstructure:"target_port,omitempty" flag:"target-port" desc:"Optional port on the target machine to connect to. Leave empty to use the SIA gateway default."`
	NetworkName    string `json:"network_name,omitempty" mapstructure:"network_name,omitempty" flag:"network-name" desc:"The network name to use for the connection, if applicable."`
	SshPath        string `json:"ssh_path" mapstructure:"ssh_path" flag:"ssh-path" desc:"The path to the SSH client executable." default:"ssh"`
}
