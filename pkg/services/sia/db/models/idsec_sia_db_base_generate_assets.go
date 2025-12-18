package models

// Possible response formats
const (
	ResponseFormatRaw  = "raw"
	ResponseFormatJSON = "json"
)

// Possible asset types
const (
	AssetTypeProxyFullChain  = "proxy_full_chain"
	AssetTypeOracleTNSAssets = "oracle_tns_assets"
)

// IdsecSIADBBaseGenerateAssets represents the base structure for generating assets.
type IdsecSIADBBaseGenerateAssets struct {
	ConnectionMethod string `json:"connection_method" mapstructure:"connection_method" flag:"connection-method" desc:"Indicates whether to generate assets for standing or dynamic access." default:"standing" choices:"standing,dynamic"`
	ResponseFormat   string `json:"response_format" mapstructure:"response_format" flag:"response-format" desc:"Specifies the format in which to return the assets." default:"raw" choices:"raw,json"`
	Folder           string `json:"folder" mapstructure:"folder" flag:"folder" desc:"The storage location for the assest."`
}
