package models

// IdsecPCloudDeleteSafe represents the details required to delete a safe.
type IdsecPCloudDeleteSafe struct {
	SafeID string `json:"safe_id" mapstructure:"safe_id" desc:"The URL encoding of the Safe to be deleted. For special characters, enter the encoding of the special character. For example, enter %20 to represent a space" flag:"safe-id" validate:"required"`
}
