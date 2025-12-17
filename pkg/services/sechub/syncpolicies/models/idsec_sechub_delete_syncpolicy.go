package models

// IdsecSecHubDeleteSyncPolicy contains the policy id for the policy to delete
type IdsecSecHubDeleteSyncPolicy struct {
	PolicyID string `json:"policy_id" mapstructure:"policy_id" desc:"Unique identifier of the referenced policy" flag:"policy-id" validate:"required"`
}
