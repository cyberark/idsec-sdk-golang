package models

// IdsecUAPPolicyStatus defines the possible status types for a policy in UAP.
const (
	StatusTypeActive     = "Active"
	StatusTypeSuspended  = "Suspended"
	StatusTypeExpired    = "Expired"
	StatusTypeValidating = "Validating"
	StatusTypeError      = "Error"
)

// IdsecUAPPolicyStatus represents the status details of a policy.
type IdsecUAPPolicyStatus struct {
	Status            string `json:"status" validate:"required" mapstructure:"status" flag:"status" desc:"The status of the policy" choices:"Active,Suspended,Expired,Validating,Error,Warning" default:"Active"`
	StatusCode        string `json:"status_code,omitempty" mapstructure:"status_code,omitempty" flag:"status-code" desc:"The status code. maxLength: 99" validate:"max=99"`
	StatusDescription string `json:"status_description,omitempty" mapstructure:"status_description,omitempty" flag:"status-description" desc:"A description of the status. maxLength: 1000" validate:"max=1000"`
	Link              string `json:"link,omitempty" mapstructure:"link,omitempty" flag:"link" desc:"Link to documentation when available. maxLength: 255" validate:"max=255"`
}
