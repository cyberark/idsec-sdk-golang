package models

// IdsecSecHubUpdateSecretStore defines the structure for updating a secret store in the Idsec Secrets Hub.
type IdsecSecHubUpdateSecretStore struct {
	ID          string `json:"id" mapstructure:"id" flag:"secret-store-id" validate:"required" desc:"The unique identifier of the secret store to update"`
	Description string `json:"description,omitempty" mapstructure:"description,omitempty" flag:"description" desc:"A description of the secret store."`
	Name        string `json:"name" mapstructure:"name,omitempty" flag:"name" desc:"The name of the secret store. It should be unique per tenant."`
	// Data contains the specific data for the secret store type.
	Data *IdsecSecHubSecretStoreData `json:"data" mapstructure:"data" desc:"The data related to the secret store as defined in the cloud platform."`
}
