package models

// IdsecIdentityPolicyStatus constants.
const (
	PolicyStatusActive   = "Active"
	PolicyStatusInactive = "Inactive"
)

// IdsecIdentityPolicy represents the schema for identity policies.
type IdsecIdentityPolicy struct {
	PolicyName      string                 `json:"policy_name" mapstructure:"policy_name" desc:"Name of the policy"`
	PolicyStatus    string                 `json:"policy_status,omitempty" mapstructure:"policy_status" desc:"Status of the policy" choices:"Active,Inactive"`
	RevStamp        string                 `json:"rev_stamp,omitempty" mapstructure:"rev_stamp" desc:"Revision stamp of the policy"`
	Description     string                 `json:"description,omitempty" mapstructure:"description" desc:"Description of the policy"`
	RoleNames       []string               `json:"role_names,omitempty" mapstructure:"role_names" desc:"List of role names associated with the policy"`
	AuthProfileName string                 `json:"auth_profile_name,omitempty" mapstructure:"auth_profile_name" desc:"Name of the auth profile associated with the policy"`
	Settings        map[string]interface{} `json:"settings,omitempty" mapstructure:"settings" desc:"Additional settings for the policy"`
}

// IdsecIdentityPolicyInfo represents detailed information about an identity policy.
type IdsecIdentityPolicyInfo struct {
	PolicyName   string `json:"policy_name" mapstructure:"policy_name" desc:"Name of the policy"`
	PolicyStatus string `json:"policy_status,omitempty" mapstructure:"policy_status" desc:"Status of the policy" choices:"Active,Inactive"`
	Description  string `json:"description,omitempty" mapstructure:"description" desc:"Description of the policy"`
}
