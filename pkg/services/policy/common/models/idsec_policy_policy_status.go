package models

// IdsecPolicyStatus defines the possible status types for a policy in the policy service.
const (
	StatusTypeActive     = "Active"
	StatusTypeSuspended  = "Suspended"
	StatusTypeExpired    = "Expired"
	StatusTypeValidating = "Validating"
	StatusTypeError      = "Error"
	StatusTypeWarning    = "Warning"
)

// IdsecPolicyStatus represents the status details of a policy.
type IdsecPolicyStatus struct {
	Status            string `json:"status" mapstructure:"status" flag:"status" desc:"The status of the policy. Policies are created with an **Active** status. You can edit the status from **Active** to **Suspended**, or from **Suspended** to **Active**." choices:"Active,Suspended,Expired,Validating,Error,Warning" default:"Active"`
	StatusCode        string `json:"status_code,omitempty" mapstructure:"status_code,omitempty" flag:"status-code" desc:"The status code. maxLength: 99 (read-only) " validate:"max=99"`
	StatusDescription string `json:"status_description,omitempty" mapstructure:"status_description,omitempty" flag:"status-description" desc:"A description of the status. maxLength: 1000 (read-only)" validate:"max=1000"`
	Link              string `json:"link,omitempty" mapstructure:"link,omitempty" flag:"link" desc:"Link to documentation when available. maxLength: 255 (read-only) " validate:"max=255"`
}
