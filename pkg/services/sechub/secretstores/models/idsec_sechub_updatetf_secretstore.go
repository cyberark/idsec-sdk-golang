// Package models for IdsecSecHubSecretStore
package models

// IdsecSecHubUpdateTfSecretStore defines the structure for updating a Terraform secret store in the Idsec Secrets Hub for consistency with the existing update secret store structure, but specifically for Terraform secret stores.
type IdsecSecHubUpdateTfSecretStore struct {
	ID          string `json:"id" mapstructure:"id" validate:"required" desc:"The unique identifier of the secret store to update"`
	Description string `json:"description,omitempty" mapstructure:"description,omitempty" desc:"A description of the secret store."`
	Name        string `json:"name" mapstructure:"name,omitempty" desc:"The name of the secret store. It should be unique per tenant."`
	State       string `json:"state" mapstructure:"state" desc:"The secret store state. Valid values: ENABLED,DISABLED" default:"ENABLED" choices:"ENABLED,DISABLED"`
	// Data contains the specific data for the secret store type.
	Data *IdsecSecHubSecretStoreData `json:"data" mapstructure:"data" desc:"The data related to the secret store as defined in the cloud platform."`
}
