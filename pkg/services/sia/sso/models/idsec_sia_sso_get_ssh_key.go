package models

// OpenSSH and PPK are supported SSH key formats for SSO SSH key retrieval.
const (
	OpenSSH       = "openssh"
	PPK           = "ppk"
	PEM_FILE_TYPE = "pem"
	PPK_FILE_TYPE = "ppk"
)

// IdsecSIASSOGetSSHKey is a struct that represents the request for getting SSH key from the Idsec SIA SSO service.
type IdsecSIASSOGetSSHKey struct {
	Folder string `json:"folder" mapstructure:"folder" flag:"folder" desc:"Output folder to write the ssh key to" default:"~/.ssh"`
	Format string `json:"format" mapstructure:"format" flag:"format" desc:"Format of the ssh key (openssh,ppk)" default:"openssh" choices:"openssh,ppk"`
}
