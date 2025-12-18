package models

// IdsecSIAIsSSHPublicKeyInstalled is a struct that represents the parameters to check if an SSH public key is installed on a target machine
type IdsecSIAIsSSHPublicKeyInstalled struct {
	TargetMachine      string `json:"target_machine" mapstructure:"target_machine" flag:"target-machine" desc:"The target machine on which to uninstall the SSH public key."`
	Username           string `json:"username" mapstructure:"username" flag:"username" desc:"The username to use to connect to the target machine via SSH."`
	Password           string `json:"password,omitempty" mapstructure:"password" flag:"password" desc:"The password to use to connect to the target machine via SSH."`
	PrivateKeyPath     string `json:"private_key_path,omitempty" mapstructure:"private_key_path" flag:"private-key-path" desc:"The private key file path to use to connect to the target machine via SSH."`
	PrivateKeyContents string `json:"private_key_contents,omitempty" mapstructure:"private_key_contents" flag:"private-key-contents" desc:"The private key contents to use to connect to the target machine via SSH."`
	Shell              string `json:"shell" mapstructure:"shell" flag:"shell" desc:"The shell to use on the target machine (bash, kornShell)." default:"bash" choices:"bash,kornShell"`
	RetryCount         int    `json:"retry_count" mapstructure:"retry_count" flag:"retry-count" desc:"The number of times to retry to connect, if it fails." default:"10"`
	RetryDelay         int    `json:"retry_delay" mapstructure:"retry_delay" flag:"retry-delay" desc:"The delay (in seconds) between retries." default:"5"`
}
