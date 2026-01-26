package models

// IdsecPCloudGetSafeMember represents the details required to get a safe member's details.
type IdsecPCloudGetSafeMember struct {
	SafeID     string `json:"safe_id" mapstructure:"safe_id" desc:"The URL encoding of the Safe name. For special characters, enter the encoding of the special character. For example, enter %20 to represent a space" flag:"safe-id" validate:"required"`
	MemberName string `json:"member_name" mapstructure:"member_name" desc:"The Vault user name, Domain user name or group name of the Safe member" flag:"member-name" validate:"required"`
}
