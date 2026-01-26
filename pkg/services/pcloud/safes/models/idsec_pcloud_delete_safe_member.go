package models

// IdsecPCloudDeleteSafeMember represents the details required to remove a safe member.
type IdsecPCloudDeleteSafeMember struct {
	SafeID     string `json:"safe_id" mapstructure:"safe_id" desc:"The URL encoding of the Safe from which the member should be deleted. For special characters, enter the encoding of the special character. For example, enter %20 to represent a space" flag:"safe-id" validate:"required"`
	MemberName string `json:"member_name" mapstructure:"member_name" desc:"The name of the Safe member to delete from the Safe’s list of members" flag:"member-name" validate:"required"`
}
