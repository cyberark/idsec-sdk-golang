package models

// Possible output formats for Idsec SIA SSO
const (
	File       string = "file"
	SingleFile string = "single_file"
	Raw        string = "raw"
	Base64     string = "base64"
)

// IdsecSIASSOGetShortLivedClientCertificate is a struct that represents the request for getting a short-lived client certificate from the Idsec SIA SSO service.
type IdsecSIASSOGetShortLivedClientCertificate struct {
	AllowCaching bool   `json:"allow_caching" mapstructure:"allow_caching" flag:"allow-caching" desc:"Indicates whether to allow short-lived token caching." default:"false"`
	Folder       string `json:"folder" validate:"required" mapstructure:"folder" flag:"folder" desc:"The output folder to which the the key / certificate are written. Required if format is File."`
	OutputFormat string `json:"output_format" mapstructure:"output_format" flag:"output-format" desc:"The output format of the key / ' 'certificate. For example, File, Raw, or Base64." default:"file" choices:"file,single_file,raw,base64"`
	Service      string `json:"service" validate:"required" mapstructure:"service" flag:"service" desc:"The service for which to generate the short-lived certificate - DPA-DB, DPA-K8S." choices:"DPA-DB,DPA-K8S"`
}
