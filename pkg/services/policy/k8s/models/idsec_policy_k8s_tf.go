package models

// IdsecPolicyK8sPolicyList is the Terraform provider output for listing K8s cluster access policies.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used outside the Terraform provider.
// It exists because ListPoliciesBy returns a channel of pages; TfListPoliciesBy drains that channel into this flat struct.
type IdsecPolicyK8sPolicyList struct {
	Policies []IdsecPolicyK8sPolicy `json:"policies" mapstructure:"policies" flag:"policies" desc:"The list of K8s cluster access policies matching the provided filters."`
}

// IdsecPolicyK8sPolicyStatus is the Terraform provider output for a K8s policy status lookup.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used outside the Terraform provider.
// It exists because PolicyStatus returns a bare string; TfPolicyStatus wraps it for Terraform state mapping.
type IdsecPolicyK8sPolicyStatus struct {
	Status string `json:"status" mapstructure:"status" flag:"status" desc:"The status of the K8s cluster access policy."`
}
