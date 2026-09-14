package models

// IdsecPCloudDeleteUser represents the input for deleting a Vault user.
type IdsecPCloudDeleteUser struct {
	UserID int `json:"user_id" mapstructure:"user_id" flag:"user-id" desc:"Numeric ID of the Vault user to delete" validate:"required"`
}
