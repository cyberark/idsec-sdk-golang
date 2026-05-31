// Package models defines request and response models for the policy API.
package models

// IdsecPolicyAccessApprovalCondition determines whether additional approval is required
// before access to a target for an eligible identity can be elevated.
type IdsecPolicyAccessApprovalCondition struct {
	Required  bool                   `json:"required" mapstructure:"required" flag:"required" desc:"Set to true if an identity requires additional approval to elevate access to a target defined in this policy; otherwise set to false."`
	Approvers []IdsecPolicyPrincipal `json:"approvers,omitempty" mapstructure:"approvers,omitempty" flag:"approvers" desc:"Up to 5 identities responsible for handling an access request. If empty, requests are sent to workspace delegates." validate:"max=5"`
}
