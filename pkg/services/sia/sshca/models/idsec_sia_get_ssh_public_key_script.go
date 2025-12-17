package models

// IdsecSIAGetSSHPublicKeyScript is a struct that represents where to output the SSH Public Key Script
type IdsecSIAGetSSHPublicKeyScript struct {
	OutputFile string `json:"output_file" mapstructure:"output_file" flag:"output-file" desc:"Path to the file where the SSH Public Key will be saved."`
	Shell      string `json:"shell" mapstructure:"shell" flag:"shell" desc:"Shell to use for the public key script (bash,kornShell)" default:"bash" choices:"bash,kornShell"`
}
