package models

// IdsecIdentityCreatePolicy represents the schema for creating a new identity policy.
type IdsecIdentityCreatePolicy struct {
	PolicyName       string                 `json:"policy_name" mapstructure:"policy_name" flag:"policy-name" desc:"Name of the policy to create"`
	PolicyStatus     string                 `json:"policy_status,omitempty" mapstructure:"policy_status" flag:"policy-status" desc:"Status of the policy to create" choices:"Active,Inactive" default:"Active"`
	Description      string                 `json:"description,omitempty" mapstructure:"description" flag:"description" desc:"Description of the policy to create"`
	RoleNames        []string               `json:"role_names,omitempty" mapstructure:"role_names" flag:"role-names" desc:"List of role names associated with the policy"`
	AuthProfileName  string                 `json:"auth_profile_name,omitempty" mapstructure:"auth_profile_name" flag:"auth-profile-name" desc:"Name of the auth profile associated with the policy"`
	Settings         map[string]interface{} `json:"settings,omitempty" mapstructure:"settings" flag:"settings" desc:"Additional settings for the policy"`
	DoNotUseDefaults bool                   `json:"do_not_use_defaults,omitempty" mapstructure:"do_not_use_defaults" flag:"do-not-use-defaults" desc:"Indicates whether to avoid using default settings when creating the policy"`
	BeforePolicy     string                 `json:"before_policy,omitempty" mapstructure:"before_policy" flag:"before-policy" desc:"Name of an existing policy to place this policy before in the order of policies, If both are given, the before policy will be prioritized and the new policy will be added before the given existing policy. If none given, the new policy will be added at the start / top prioritized of the policies list."`
	AfterPolicy      string                 `json:"after_policy,omitempty" mapstructure:"after_policy" flag:"after-policy" desc:"Name of an existing policy to place this policy after in the order of policies, If both are given, the before policy will be prioritized and the new policy will be added before the given existing policy. If none given, the new policy will be added at the start / top prioritized of the policies list."`
}
