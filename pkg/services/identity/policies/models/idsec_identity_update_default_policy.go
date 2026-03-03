package models

// IdsecIdentityUpdatePolicy represents the schema for updating an identity policy.
type IdsecIdentityUpdateDefaultPolicy struct {
	PolicyStatus    string                 `json:"policy_status,omitempty" mapstructure:"policy_status" flag:"policy-status" desc:"Updated status of the policy" choices:"Active,Inactive"`
	Description     string                 `json:"description,omitempty" mapstructure:"description" flag:"description" desc:"Updated description of the policy"`
	RoleNames       []string               `json:"role_names,omitempty" mapstructure:"role_names" flag:"role-names" desc:"Updated list of role names associated with the policy"`
	AuthProfileName string                 `json:"auth_profile_name,omitempty" mapstructure:"auth_profile_name" flag:"auth-profile-name" desc:"Updated name of the auth profile associated with the policy"`
	Settings        map[string]interface{} `json:"settings,omitempty" mapstructure:"settings" flag:"settings" desc:"Updated additional settings for the policy"`
	BeforePolicy    string                 `json:"before_policy,omitempty" mapstructure:"before_policy" flag:"before-policy" desc:"Name of an existing policy to place this policy before in the order of policies, If both are given, the before policy will be prioritized and the new policy will be added before the given existing policy. If none given, the new policy will be added at the start / top prioritized of the policies list."`
	AfterPolicy     string                 `json:"after_policy,omitempty" mapstructure:"after_policy" flag:"after-policy" desc:"Name of an existing policy to place this policy after in the order of policies, If both are given, the before policy will be prioritized and the new policy will be added before the given existing policy. If none given, the new policy will be added at the start / top prioritized of the policies list."`
}
