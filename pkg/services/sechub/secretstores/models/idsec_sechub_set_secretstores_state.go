package models

// IdsecSecHubSetSecretStoresState represents the body of sent when setting multiple secret store states
type IdsecSecHubSetSecretStoresState struct {
	Action         string   `json:"action" mapstructure:"action" flag:"action" desc:"State to set secret stores to (enable,disable)" choices:"enable,disable"`
	SecretStoreIDs []string `json:"secret_store_ids" mapstructure:"secret_store_ids" desc:"List of Secret Store ids to set state for" flag:"secret-store-ids" validate:"required"`
}

// IdsecSecHubSetSecretStoresStateResults represents the individual object for each secret store for which
// the secret store state was set
type IdsecSecHubSetSecretStoresStateResults struct {
	SecretStoreID string `json:"secret_store_id" mapstructure:"secret_store_id"`
	Result        string `json:"result" mapstructure:"result"`
	ErrorMessage  string `json:"error_message" mapstructure:"error_message"`
}

// IdsecSecHubSetSecretStoresStateResponse is the outer object which contains the indvidual secret store state
// response objects
type IdsecSecHubSetSecretStoresStateResponse struct {
	Results []IdsecSecHubSetSecretStoresStateResults `json:"results" mapstructure:"results"`
}
