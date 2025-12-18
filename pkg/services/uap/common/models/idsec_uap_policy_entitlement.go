package models

// Possible values for PolicyType
const (
	PolicyTypeRecurring = "Recurring"
	PolicyTypeOnDemand  = "OnDemand"
)

// IdsecUAPPolicyEntitlement represents the entitlement details of a policy.
type IdsecUAPPolicyEntitlement struct {
	TargetCategory string `json:"target_category" validate:"required" mapstructure:"target_category" flag:"target-category" desc:"The category of the target: Cloud access: Cloud console; Infrastructure access: VM, DB" choices:"Cloud console,VM,DB"`
	LocationType   string `json:"location_type" validate:"required" mapstructure:"location_type" flag:"location-type" desc:"The location of the target: Cloud access: AWS, Azure, GCP; Infrastructure access: FQDN/IP" choices:"AWS,Azure,GCP,FQDN/IP"`
	PolicyType     string `json:"policy_type" validate:"required" mapstructure:"policy_type" flag:"policy-type" desc:"The type of policy - Recurring (Cloud console, VM or DB only) or OnDemand. Default - Recurring. required" choices:"Recurring,OnDemand" default:"Recurring"`
}
