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
	Folder string `json:"folder" mapstructure:"folder" flag:"folder" desc:"The output folder where the SSH key is written." default:"~/.ssh"`
	Format string `json:"format" mapstructure:"format" flag:"format" desc:"The format of the SSH key (openssh, ppk)." default:"openssh" choices:"openssh,ppk"`
}
