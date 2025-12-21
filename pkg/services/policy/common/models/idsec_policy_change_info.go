package models

// IdsecPolicyChangeInfo captures change information for a policy.
type IdsecPolicyChangeInfo struct {
	User string `json:"user,omitempty" mapstructure:"user,omitempty" flag:"user" desc:"Username of the user who made the change" validate:"omitempty,min=1,max=512,regexp=^[\\w.+\\-@#]+$"`
	Time string `json:"time,omitempty" mapstructure:"time,omitempty" flag:"time" desc:"Time of the change"`
}
