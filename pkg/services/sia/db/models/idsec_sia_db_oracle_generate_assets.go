package models

// IdsecSIADBOracleGenerateAssets represents the structure for generating Oracle assets.
type IdsecSIADBOracleGenerateAssets struct {
	IdsecSIADBBaseGenerateAssets `mapstructure:",squash"`
	Unzip                      bool `json:"unzip" mapstructure:"unzip" flag:"unzip" desc:"Indicates whether to save the file zipped." default:"true"`
	IncludeSSO                 bool `json:"include_sso" mapstructure:"include_sso" flag:"include-sso" desc:"Indicates whether to generate the asset with SSO details." default:"true"`
}
