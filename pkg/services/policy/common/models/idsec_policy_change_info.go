package models

// IdsecPolicyChangeInfo captures change information for a policy.
type IdsecPolicyChangeInfo struct {
	User string `json:"user,omitempty" mapstructure:"user,omitempty" flag:"user" desc:"The name of the user that modified the policy (read-only) minLength: 1 maxLength: 512 readOnly: true" validate:"omitempty,min=1,max=512,regexp=^[\\w.+\\-@#]+$"`
	Time string `json:"time,omitempty" mapstructure:"time,omitempty" flag:"time" desc:"The date and time the policy was created or modified (read-only) readOnly: true"`
}
