package models

// IdsecUAPConditions represents the conditions for UAP policies.
type IdsecUAPConditions struct {
	AccessWindow       IdsecUAPTimeCondition `json:"access_window" validate:"required" mapstructure:"access_window" flag:"access-window" desc:"The days and times when the user can connect to their target using this policy"`
	MaxSessionDuration int                   `json:"max_session_duration" mapstructure:"max_session_duration" flag:"max-session-duration" desc:"The maximum length of time (in hours) a user can remain connected in a single session. Default: 1" validate:"required,min=1,max=24" default:"1"`
}
