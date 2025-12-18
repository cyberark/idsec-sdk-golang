package models

// IdsecSIAGetSSHPublicKeyScript is a struct that represents where to output the SSH Public Key Script
type IdsecSIAGetSSHPublicKeyScript struct {
	OutputFile string `json:"output_file" mapstructure:"output_file" flag:"output-file" desc:"The path to the file where the SSH public key will be saved."`
	Shell      string `json:"shell" mapstructure:"shell" flag:"shell" desc:"The shell to use for the public key script (bash, kornShell)." default:"bash" choices:"bash,kornShell"`
}
