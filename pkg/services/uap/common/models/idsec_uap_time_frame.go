package models

// IdsecUAPTimeFrame represents the time frame for a policy.
type IdsecUAPTimeFrame struct {
	FromTime string `json:"from_time,omitempty" mapstructure:"from_time,omitempty" flag:"from-time" desc:"pattern: yyyy-MM-ddTHH:mm:ss; The date the policy becomes active (in ISO 8601 format e.g. 2000-01-30T13:00:00)"`
	ToTime   string `json:"to_time,omitempty" mapstructure:"to_time,omitempty" flag:"to-time" desc:"pattern: yyyy-MM-ddTHH:mm:ss; The date the policy expires (in ISO 8601 format e.g. 2000-02-30T13:00:00)"`
}
