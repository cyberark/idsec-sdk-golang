package models

// IdsecSecHubDeleteSyncPolicy contains the policy id for the policy to delete
type IdsecSecHubDeleteSyncPolicy struct {
	PolicyID string `json:"id" mapstructure:"id" desc:"Unique identifier of the referenced policy" flag:"policy-id" validate:"required"`
}
