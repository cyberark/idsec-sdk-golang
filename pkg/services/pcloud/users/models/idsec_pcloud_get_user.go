package models

// IdsecPCloudGetUser represents the input for retrieving a Vault user.
type IdsecPCloudGetUser struct {
	UserID int `json:"user_id" mapstructure:"user_id" flag:"user-id" desc:"Numeric ID of the Vault user to retrieve" validate:"required"`
}
