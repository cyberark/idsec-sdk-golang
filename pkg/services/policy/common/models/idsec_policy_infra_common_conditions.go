package models

// IdsecPolicyInfraCommonConditions represents the conditions of an infrastructure
// (VM/DB) access policy.
//
// It inlines AccessWindow and MaxSessionDuration instead of embedding
// IdsecPolicyConditions, because AccessWindow uses the 4-digit "HH:MM"
// IdsecPolicyInfraTimeCondition that the infrastructure backend requires,
// distinct from the 6-digit "HH:MM:SS" format the other policy types use.
//
// AccessApproval (dual control) is shared here rather than split into
// per-policy-type conditions structs: VM and DB policies both need the field
// to exist so it round-trips through Terraform/CLI schemas and can be
// explicitly rejected/accepted by the respective service layer, but the
// actual support differs -- see the field's own description below.
type IdsecPolicyInfraCommonConditions struct {
	AccessWindow       IdsecPolicyInfraTimeCondition `json:"access_window" mapstructure:"access_window" flag:"access-window" desc:"The days and times when the user can connect to their target using this policy, using 4-digit HH:MM hours"`
	MaxSessionDuration int                           `json:"max_session_duration" mapstructure:"max_session_duration" flag:"max-session-duration" desc:"The maximum length of time (in hours) a user can remain connected in a single session. Default: 1" validate:"required,min=1,max=24" default:"1"`
	IdleTime           int                           `json:"idle_time,omitempty" mapstructure:"idle_time,omitempty" flag:"idle-time" desc:"The maximum idle time before the session ends, in minutes." validate:"gt=0,lte=120" default:"10"`
	// AccessApproval is a pointer so that callers who never configure dual control never send
	// the field at all (Go's json.Marshal ignores "omitempty" on non-pointer structs, so a value
	// type here would always serialize "access_approval":{"required":false}). Leaving this pointer
	// unset keeps the request byte-identical to policies created before dual control existed.
	AccessApproval *IdsecPolicyAccessApprovalCondition `json:"access_approval,omitempty" mapstructure:"access_approval,omitempty" flag:"access-approval" desc:"Determines whether additional approval (dual control) is required before access to a target for an eligible identity can be elevated. Supported for VM policies only, and not on all tenants -- if dual control isn't enabled for the tenant, the backend rejects the request with a clear error. Not supported for DB policies at all: setting required=true will cause DB policy creation or update to fail immediately."`
}
