package models

// Possible values for DelegationClassification
const (
	DelegationClassificationUnrestricted = "Unrestricted"
	DelegationClassificationRestricted   = "Restricted"
)

// IdsecPolicyCommonAccessPolicy represents an access policy in the policy service.
type IdsecPolicyCommonAccessPolicy struct {
	Metadata                 IdsecPolicyMetadata    `json:"metadata,omitempty" mapstructure:"metadata,omitempty" flag:"metadata" desc:"Policy metadata id name and extra information"`
	Principals               []IdsecPolicyPrincipal `json:"principals,omitempty" mapstructure:"principals,omitempty" flag:"principals" desc:"List of users, groups and roles that the policy applies to"`
	DelegationClassification string                 `json:"delegation_classification" mapstructure:"delegation_classification" flag:"delegation-classification" desc:"Indicates the user rights for the current policy" choices:"Restricted,Unrestricted" default:"Unrestricted"`
}
