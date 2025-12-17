package models

// Possible token types for Idsec SIA SSO
const (
	Password          string = "password"
	ClientCertificate string = "client_certificate"
	OracleWallet      string = "oracle_wallet"
	RDPFile           string = "rdp_file"
)

// IdsecSIASSOGetTokenInfo is a struct that represents the request for getting token information from the Idsec SIA SSO service.
type IdsecSIASSOGetTokenInfo struct {
	TokenType string `json:"token_type" validate:"required" mapstructure:"token_type" flag:"token-type" desc:"Which token type to get the info for [DPA-K8S, DPA-DB, DPA-RDP, DPA-SSH]" choices:"password,client_certificate,oracle_wallet,rdp_file"`
	Service   string `json:"service" validate:"required" mapstructure:"service" flag:"service" desc:"Which service to get the token info for [password, client_certificate, oracle_wallet, rdp_file]" choice:"DPA-DB,DPA-K8S,DPA-RDP,DPA-SSH"`
}

// IdsecSIASSOTokenInfo is a struct that represents the response from the Idsec SIA SSO service for token information.
type IdsecSIASSOTokenInfo struct {
	Metadata map[string]interface{} `json:"metadata" validate:"required" mapstructure:"metadata"`
}
