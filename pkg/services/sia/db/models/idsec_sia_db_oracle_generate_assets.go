package models

// IdsecSIADBOracleGenerateAssets represents the structure for generating Oracle assets.
type IdsecSIADBOracleGenerateAssets struct {
	IdsecSIADBBaseGenerateAssets `mapstructure:",squash"`
	Unzip                        bool `json:"unzip" mapstructure:"unzip" flag:"unzip" desc:"Whether to save zipped or not" default:"true"`
	IncludeSSO                   bool `json:"include_sso" mapstructure:"include_sso" flag:"include-sso" desc:"Whether to generate the asset with SSO details" default:"true"`
}
