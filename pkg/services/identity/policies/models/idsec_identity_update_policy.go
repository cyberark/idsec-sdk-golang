package models

// IdsecIdentityUpdatePolicy represents the schema for updating an identity policy.
type IdsecIdentityUpdatePolicy struct {
	PolicyName      string                 `json:"policy_name,omitempty" mapstructure:"policy_name" flag:"policy-name" desc:"Updated name of the policy"`
	PolicyStatus    string                 `json:"policy_status,omitempty" mapstructure:"policy_status" flag:"policy-status" desc:"Updated status of the policy" choices:"Active,Inactive"`
	Description     string                 `json:"description,omitempty" mapstructure:"description" flag:"description" desc:"Updated description of the policy"`
	RoleNames       []string               `json:"role_names,omitempty" mapstructure:"role_names" flag:"role-names" desc:"Updated list of role names associated with the policy"`
	AuthProfileName string                 `json:"auth_profile_name,omitempty" mapstructure:"auth_profile_name" flag:"auth-profile-name" desc:"Updated name of the auth profile associated with the policy"`
	Settings        map[string]interface{} `json:"settings,omitempty" mapstructure:"settings" flag:"settings" desc:"Updated additional settings for the policy"`
}
