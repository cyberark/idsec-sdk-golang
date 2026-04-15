package models

// IdsecPolicyTimeFrame represents the time frame for a policy.
type IdsecPolicyTimeFrame struct {
	FromTime string `json:"from_time,omitempty" mapstructure:"from_time,omitempty" flag:"from-time" desc:"The date and time the policy becomes active (format: yyyy-MM-ddTHH:mm:ss)"`
	ToTime   string `json:"to_time,omitempty" mapstructure:"to_time,omitempty" flag:"to-time" desc:"format: yyyy-MM-ddTHH:mm:ss The date the policy expires"`
}
