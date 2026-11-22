package models

// IdsecARSCancelAccessRequest is the input for canceling an access request.
type IdsecARSCancelAccessRequest struct {
	RequestID    string `json:"request_id" mapstructure:"request_id" flag:"request-id" desc:"The access request id to cancel" validate:"required"`
	CancelReason string `json:"cancel_reason" mapstructure:"cancel_reason" flag:"cancel-reason" desc:"What is the reason for the cancel" validate:"required"`
	Poll         bool   `json:"poll,omitempty" mapstructure:"poll,omitempty" flag:"poll" desc:"Whether to poll the request after canceling it, until it finishes"`
}
