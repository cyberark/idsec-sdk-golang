package models

// IdsecSecHubGetSecretStore represents the details required to get a Secret Stores details.
type IdsecSecHubGetSecretStore struct {
	ID string `json:"id" mapstructure:"id" desc:"Secret Store id to get details for" flag:"secret-store-id" validate:"required"`
}
