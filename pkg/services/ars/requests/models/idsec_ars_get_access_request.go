package models

// IdsecARSGetAccessRequest is the input for getting an access request.
type IdsecARSGetAccessRequest struct {
	RequestID string `json:"request_id" mapstructure:"request_id" flag:"request-id" desc:"The access request id to get" validate:"required"`
}
