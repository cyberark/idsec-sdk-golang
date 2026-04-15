package models

// Possible values for DelegationClassification
const (
	DelegationClassificationUnrestricted = "Unrestricted"
	DelegationClassificationRestricted   = "Restricted"
)

// IdsecPolicyCommonAccessPolicy represents an access policy in the policy service.
type IdsecPolicyCommonAccessPolicy struct {
	Metadata                 IdsecPolicyMetadata    `json:"metadata,omitempty" mapstructure:"metadata,omitempty" flag:"metadata" desc:"The policy metadata: ID, name, and additional information"`
	Principals               []IdsecPolicyPrincipal `json:"principals,omitempty" mapstructure:"principals,omitempty" flag:"principals" desc:"The identity: user, group, role"`
	DelegationClassification string                 `json:"delegation_classification" mapstructure:"delegation_classification" flag:"delegation-classification" desc:"Indicates the user rights for the policy. Default: Unrestricted" choices:"Restricted,Unrestricted" default:"Unrestricted"`
}
