package models

// IdsecSecHubDeleteSecretStore contains the secret store ID to delete
type IdsecSecHubDeleteSecretStore struct {
	ID string `json:"id" mapstructure:"id" desc:"Secret store id to delete" flag:"secret-store-id" validate:"required"`
}
