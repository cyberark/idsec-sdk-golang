package models

// IdsecSecHubFindSecretByNameAndStoreID contains the lookup parameters for finding
// a single secret by name and store ID.
type IdsecSecHubFindSecretByNameAndStoreID struct {
	Name    string `json:"name" mapstructure:"name" desc:"Name of the secret as defined in the secret store" flag:"name" validate:"required"`
	StoreID string `json:"store_id" mapstructure:"store_id" desc:"The unique identifier of the secret store" flag:"store-id" validate:"required"`
}
