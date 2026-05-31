package models

// OpenSSH and PPK are supported SSH key formats for SSO SSH key retrieval.
const (
	OpenSSH       = "openssh"
	PPK           = "ppk"
	PEM_FILE_TYPE = "pem"
	PPK_FILE_TYPE = "ppk"
)

// SSHKeyOutputFormatFile and SSHKeyOutputFormatRaw are the supported delivery
// modes for the short-lived SSH key returned by the SSO service.
//
// They reuse the same string values as the broader SSO output-format constants
// (see idsec_sia_sso_get_short_lived_client_certificate.go) so CLI flags stay
// consistent across SSO actions.
const (
	SSHKeyOutputFormatFile = File
	SSHKeyOutputFormatRaw  = Raw
)

// IdsecSIASSOGetSSHKey is a struct that represents the request for getting SSH key from the Idsec SIA SSO service.
type IdsecSIASSOGetSSHKey struct {
	AllowCaching bool   `json:"allow_caching,omitempty" mapstructure:"allow_caching,omitempty" flag:"allow-caching" desc:"Indicates whether to allow short-lived ssh key caching." default:"false"`
	Folder       string `json:"folder,omitempty" mapstructure:"folder,omitempty" flag:"folder" desc:"The output folder where the SSH key is written. Required when output-format is file." default:"~/.ssh"`
	Format       string `json:"format" mapstructure:"format" flag:"format" desc:"The format of the SSH key (openssh, ppk)." default:"openssh" choices:"openssh,ppk"`
	OutputFormat string `json:"output_format,omitempty" mapstructure:"output_format,omitempty" flag:"output-format" desc:"How the SSH key is returned: 'file' writes to folder and returns its path; 'raw' returns the key content directly without touching disk." default:"file" choices:"file,raw"`
}
