package models

// Possible wallet types for Idsec SIA SSO
const (
	PEM string = "PEM"
	SSO string = "SSO"
)

// IdsecSIASSOGetShortLivedOracleWallet is a struct that represents the request for getting a short-lived Oracle wallet from the Idsec SIA SSO service.
type IdsecSIASSOGetShortLivedOracleWallet struct {
	AllowCaching bool   `json:"allow_caching" mapstructure:"allow_caching" flag:"allow-caching" desc:"Indicates whether to allow short-lived token caching." default:"false"`
	UnzipWallet  bool   `json:"unzip_wallet" mapstructure:"unzip_wallet" flag:"unzip-wallet" desc:"Indicates whether to save the wallet as a ZIP file." default:"true"`
	Folder       string `json:"folder" validate:"required" mapstructure:"folder" flag:"folder" desc:"The output folder to which the wallet is written."`
	WalletType   string `json:"wallet_type" mapstructure:"wallet_type" flag:"wallet-type" desc:"The type of wallet to generate. If PEM, no zip will be generated, only an ewallet.pem file." default:"SSO" choices:"PEM,SSO"`
}
