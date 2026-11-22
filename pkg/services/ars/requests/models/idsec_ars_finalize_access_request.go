package models

// IdsecARSFinalizeAccessRequest is the input for finalizing (approving / rejecting) an access request.
type IdsecARSFinalizeAccessRequest struct {
	RequestID          string                 `json:"request_id" mapstructure:"request_id" flag:"request-id" desc:"Which request to finalize" validate:"required"`
	Result             string                 `json:"result" mapstructure:"result" flag:"result" desc:"The finalized result" choices:"APPROVED,REJECTED,CANCELED,FAILED,UNKNOWN" validate:"required,oneof=APPROVED REJECTED CANCELED FAILED UNKNOWN"`
	RequestDetails     map[string]interface{} `json:"request_details,omitempty" mapstructure:"request_details,omitempty" flag:"request-details" desc:"Optionally, the request details related to the request that needs to be updated"`
	FinalizationReason string                 `json:"finalization_reason,omitempty" mapstructure:"finalization_reason,omitempty" flag:"finalization-reason" desc:"If rejected, what is the reason for the rejection"`
	Poll               bool                   `json:"poll,omitempty" mapstructure:"poll,omitempty" flag:"poll" desc:"Whether to poll the request after finalizing it, until it reaches pending state or finishes (or only finishes, if wait-until-finished is set)"`
	WaitUntilFinished  bool                   `json:"wait_until_finished,omitempty" mapstructure:"wait_until_finished,omitempty" flag:"wait-until-finished" desc:"If polling, whether to wait until the request finishes, instead of only until it reaches pending state"`
}
