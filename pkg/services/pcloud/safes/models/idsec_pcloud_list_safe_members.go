package models

// IdsecPCloudListSafeMembers represents the details required to list the members of a safe.
type IdsecPCloudListSafeMembers struct {
	SafeID string `json:"safe_id" mapstructure:"safe_id" desc:"The URL encoding of the Safe name to retreive the Safe's members. For special characters, enter the encoding of the special character. For example, enter %20 to represent a space" flag:"safe-id" validate:"required"`
}
