package models

// IdsecSIAInstallSSHPublicKey is a struct that represents the parameters needed to install an SSH public key on a target machine.
type IdsecSIAInstallSSHPublicKey struct {
	TargetMachine      string `json:"target_machine" mapstructure:"target_machine" flag:"target-machine" desc:"Target machine on which to install the ssh public key on"`
	Username           string `json:"username" mapstructure:"username" flag:"username" desc:"Username to connect with to the target machine via ssh"`
	Password           string `json:"password,omitempty" mapstructure:"password" flag:"password" desc:"Password to connect with to the target machine via ssh"`
	PrivateKeyPath     string `json:"private_key_path,omitempty" mapstructure:"private_key_path" flag:"private-key-path" desc:"Private key file path to use for connecting to the target machine via ssh"`
	PrivateKeyContents string `json:"private_key_contents,omitempty" mapstructure:"private_key_contents" flag:"private-key-contents" desc:"Private key contents to use for connecting to the target machine via ssh"`
	Shell              string `json:"shell" mapstructure:"shell" flag:"shell" desc:"Shell to use on the target machine (bash,kornShell)" default:"bash" choices:"bash,kornShell"`
	RetryCount         int    `json:"retry_count" mapstructure:"retry_count" flag:"retry-count" desc:"Number of times to retry to connect if it fails" default:"10"`
	RetryDelay         int    `json:"retry_delay" mapstructure:"retry_delay" flag:"retry-delay" desc:"Delay in seconds between retries" default:"5"`
}
