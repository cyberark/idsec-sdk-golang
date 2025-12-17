package models

// IdsecSIASMGetSession represents the request to get a session by ID.
type IdsecSIASMGetSession struct {
	SessionID string `json:"session_id" mapstructure:"session_id" flag:"session-id" desc:"Session identifier to get" validate:"required"`
}
