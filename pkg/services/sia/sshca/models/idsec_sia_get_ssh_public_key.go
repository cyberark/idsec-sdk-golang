package models

// IdsecSIAGetSSHPublicKey is a struct that represents where to output the SSH Public Key
type IdsecSIAGetSSHPublicKey struct {
	OutputFile string `json:"output_file" mapstructure:"output_file" flag:"output-file" desc:"The path to the file where the SSH public key will be saved."`
}
