package models

// IdsecSIAGetSSHPublicKey is a struct that represents where to output the SSH Public Key
type IdsecSIAGetSSHPublicKey struct {
	OutputFile string `json:"output_file" mapstructure:"output_file" flag:"output-file" desc:"Path to the file where the SSH Public Key will be saved."`
}
