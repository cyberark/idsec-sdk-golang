package models

// IdsecAccessAssetsSecretRequest represents the request to retrieve a secret for an asset.
type IdsecAccessAssetsSecretRequest struct {
	AssetID string `json:"asset_id" mapstructure:"asset_id" flag:"asset-id" desc:"Identifier of the asset to retrieve the secret for" validate:"required"`
	Reason  string `json:"reason,omitempty" mapstructure:"reason,omitempty" flag:"reason" desc:"Optional audit reason for retrieving the secret"`
}

// IdsecAccessAssetsSecretResponse represents the response containing the asset secret.
type IdsecAccessAssetsSecretResponse struct {
	AssetID string  `json:"assetId" mapstructure:"asset_id" desc:"Identifier of the asset"`
	Secret  *string `json:"secret" mapstructure:"secret" desc:"The secret value"`
}
