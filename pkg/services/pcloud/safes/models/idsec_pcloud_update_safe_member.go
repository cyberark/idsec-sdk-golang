package models

// IdsecPCloudUpdateSafeMember represents the details required to update a safe member.
type IdsecPCloudUpdateSafeMember struct {
	SafeID                   string                            `json:"safe_id" mapstructure:"safe_id" desc:"The URL encoding of the Safe name. For special characters, enter the encoding of the special character. For example, enter %20 to represent a space" flag:"safe-id" validate:"required"`
	MemberName               string                            `json:"member_name" mapstructure:"member_name" desc:"The Vault user name, Domain user name or group name of the Safe member to update. Special characters cannot be used in the Safe member name: \\ / : * < > “ | ? % & +" flag:"member-name" validate:"required"`
	MembershipExpirationDate int                               `json:"membership_expiration_date,omitempty" mapstructure:"membership_expiration_date,omitempty" desc:"User's Safe membership expiration date to be updated" flag:"membership-expiration-date"`
	Permissions              *IdsecPCloudSafeMemberPermissions `json:"permissions,omitempty" mapstructure:"permissions,omitempty" desc:"User or group permissions in the Safe to be updated" flag:"permissions"`
	PermissionSet            string                            `json:"permission_set,omitempty" mapstructure:"permission_set,omitempty" desc:"Predefined permission set to be updated (connect_only,read_only,approver,accounts_manager,full,custom)" flag:"permission-set" choices:"connect_only,read_only,approver,accounts_manager,full,custom"`
}
