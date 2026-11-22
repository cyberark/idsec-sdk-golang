package models

// IdsecARSSubmitAccessRequest is the input for submitting a new access request.
type IdsecARSSubmitAccessRequest struct {
	TargetCategory    string                 `json:"target_category" mapstructure:"target_category" flag:"target-category" desc:"What is the category that is required to execute" choices:"CLOUD_CONSOLE,VM,GROUP" validate:"required,oneof=CLOUD_CONSOLE VM GROUP"`
	RequestType       string                 `json:"request_type,omitempty" mapstructure:"request_type,omitempty" flag:"request-type" desc:"The type of request to start" default:"ON_DEMAND" choices:"DUAL_CONTROL,ON_DEMAND" validate:"omitempty,oneof=DUAL_CONTROL ON_DEMAND"`
	RequestDetails    map[string]interface{} `json:"request_details,omitempty" mapstructure:"request_details,omitempty" flag:"request-details" desc:"The details related to the workload"`
	Association       map[string]interface{} `json:"association,omitempty" mapstructure:"association,omitempty" flag:"association" desc:"Optionally an associated policy"`
	Poll              bool                   `json:"poll,omitempty" mapstructure:"poll,omitempty" flag:"poll" desc:"Whether to poll the request after submitting it, until it reaches pending state (or finishes, if wait-until-finished is set)"`
	WaitUntilFinished bool                   `json:"wait_until_finished,omitempty" mapstructure:"wait_until_finished,omitempty" flag:"wait-until-finished" desc:"If polling, whether to wait until the request finishes, instead of only until it reaches pending state"`
}
