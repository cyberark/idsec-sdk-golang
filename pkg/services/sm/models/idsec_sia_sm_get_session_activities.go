package models

// IdsecSIASMGetSessionActivities represents the request to get a session activities by ID.
type IdsecSIASMGetSessionActivities struct {
	SessionID string `json:"session_id" mapstructure:"session_id" flag:"session-id" desc:"Session identifier to get the activities for'" validate:"required"`
}
