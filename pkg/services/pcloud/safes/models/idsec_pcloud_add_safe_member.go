package models

// IdsecPCloudAddSafeMember represents the details required to add a safe member.
type IdsecPCloudAddSafeMember struct {
	SafeID                   string                            `json:"safe_id" mapstructure:"safe_id" desc:"The URL encoding of the Safe name. For special characters, enter the encoding of the special character. For example, enter %20 to represent a space" flag:"safe-id" validate:"required"`
	MemberName               string                            `json:"member_name" mapstructure:"member_name" desc:"The user name or group name of the Safe member. Do not use the following characters: \\ / : * < > “ | ? % & +" flag:"member-name" validate:"required"`
	MemberType               string                            `json:"member_type" mapstructure:"member_type" desc:"The member type (User,Group,Role)" flag:"member-type" validate:"required" choices:"User,Group,Role"`
	SearchIn                 string                            `json:"search_in,omitempty" mapstructure:"search_in,omitempty" desc:"Where to search. Search within the domain using the domain ID, or within the Vault for a system component user. Retrieve the domain ID (also known as Identity Directory ID - UUID - using a POST request to {{baseUrl}/Core/GetDirectoryServices" flag:"search-in"`
	MembershipExpirationDate int                               `json:"membership_expiration_date,omitempty" mapstructure:"membership_expiration_date,omitempty" desc:"The member's expiration date for this Safe. For members with no expiration date, this value is null" flag:"membership-expiration-date"`
	Permissions              *IdsecPCloudSafeMemberPermissions `json:"permissions,omitempty" mapstructure:"permissions,omitempty" desc:"The permissions that the user or group has on this Safe"`
	PermissionSet            string                            `json:"permission_set" mapstructure:"permission_set,omitempty" desc:"Predefined permission set to use (connect_only,read_only,approver,accounts_manager,full,custom)" flag:"permission-set" default:"read_only" choices:"connect_only,read_only,approver,accounts_manager,full,custom"`
}
