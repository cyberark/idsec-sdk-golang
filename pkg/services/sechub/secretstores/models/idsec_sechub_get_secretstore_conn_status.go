package models

// IdsecSecHubGetSecretStoreConnectionStatus contains the secret store ID for which you wish to retrieve
// the connection status
type IdsecSecHubGetSecretStoreConnectionStatus struct {
	SecretStoreID string `json:"secret_store_id" mapstructure:"secret_store_id" desc:"Secret Store id to get connection status for" flag:"secret-store-id" validate:"required"`
}

// IdsecSecHubGetSecretStoreConnectionStatusResponse holds the connection status response
type IdsecSecHubGetSecretStoreConnectionStatusResponse struct {
	Message string `json:"message" mapstructure:"message" desc:"A message containing extra information from the connection test."`
	Status  string `json:"status" mapstructure:"status" desc:"The connection test result. Allowed Values: OK, ERROR."`
}
