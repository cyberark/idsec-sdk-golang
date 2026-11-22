package models

// IdsecARSAccessRequestState is the current state of an access request.
type IdsecARSAccessRequestState string

// Access request states.
const (
	RequestStateStarting IdsecARSAccessRequestState = "STARTING"
	RequestStateRunning  IdsecARSAccessRequestState = "RUNNING"
	RequestStatePending  IdsecARSAccessRequestState = "PENDING"
	RequestStateFinished IdsecARSAccessRequestState = "FINISHED"
	RequestStateExpired  IdsecARSAccessRequestState = "EXPIRED"
)

// IdsecARSAccessRequestResult is the result of an access request.
type IdsecARSAccessRequestResult string

// Access request results.
const (
	RequestResultApproved IdsecARSAccessRequestResult = "APPROVED"
	RequestResultRejected IdsecARSAccessRequestResult = "REJECTED"
	RequestResultCanceled IdsecARSAccessRequestResult = "CANCELED"
	RequestResultFailed   IdsecARSAccessRequestResult = "FAILED"
	RequestResultUnknown  IdsecARSAccessRequestResult = "UNKNOWN"
)

// IdsecARSAccessRequest represents an access request.
// The list API returns a reduced form (request id, category, link, state and creation / last update times)
// unless the extended filter flag is set, in which case items carry the full request.
type IdsecARSAccessRequest struct {
	RequestID          string                              `json:"request_id" mapstructure:"request_id" desc:"ID of the request"`
	TargetCategory     string                              `json:"target_category" mapstructure:"target_category" desc:"Target category the request is related to"`
	RequestLink        string                              `json:"request_link,omitempty" mapstructure:"request_link,omitempty" desc:"Link to the request itself"`
	RequestState       IdsecARSAccessRequestState          `json:"request_state" mapstructure:"request_state" desc:"Current request state"`
	RequestResult      IdsecARSAccessRequestResult         `json:"request_result,omitempty" mapstructure:"request_result,omitempty" desc:"Result of the request"`
	RequestDetails     map[string]interface{}              `json:"request_details,omitempty" mapstructure:"request_details,omitempty" desc:"Details given to this request"`
	RequestApprovers   []map[string]interface{}            `json:"request_approvers,omitempty" mapstructure:"request_approvers,omitempty" desc:"Related entities who approved or rejected the request"`
	RequestOutcomes    map[string]interface{}              `json:"request_outcomes,omitempty" mapstructure:"request_outcomes,omitempty" desc:"Outcomes of this request"`
	RequestSteps       map[string]interface{}              `json:"request_steps,omitempty" mapstructure:"request_steps,omitempty" desc:"Status in regards to the steps in the access request"`
	LastExecutedStep   string                              `json:"last_executed_step,omitempty" mapstructure:"last_executed_step,omitempty" desc:"Last step that was actually executed"`
	Associations       map[string][]map[string]interface{} `json:"associations,omitempty" mapstructure:"associations,omitempty" desc:"Entity associations to the request"`
	FinalizationReason string                              `json:"finalization_reason,omitempty" mapstructure:"finalization_reason,omitempty" desc:"Reason for canceling or rejecting or approving the request"`
	Requester          map[string]interface{}              `json:"requester,omitempty" mapstructure:"requester,omitempty" desc:"The requester of the request"`
	CreatedBy          string                              `json:"created_by,omitempty" mapstructure:"created_by,omitempty" desc:"Who created the request (extended response)"`
	CreatedAt          string                              `json:"created_at,omitempty" mapstructure:"created_at,omitempty" desc:"Creation time of the request (extended response)"`
	UpdatedBy          string                              `json:"updated_by,omitempty" mapstructure:"updated_by,omitempty" desc:"Who last updated the request (extended response)"`
	UpdatedAt          string                              `json:"updated_at,omitempty" mapstructure:"updated_at,omitempty" desc:"When was the request last updated (extended response)"`
	CreationTime       string                              `json:"creation_time,omitempty" mapstructure:"creation_time,omitempty" desc:"Creation time of the request (non-extended list response)"`
	LastUpdateTime     string                              `json:"last_update_time,omitempty" mapstructure:"last_update_time,omitempty" desc:"When was the request last updated (non-extended list response)"`
}

// IdsecARSAccessRequests is a single page of access requests as returned by the list API.
type IdsecARSAccessRequests struct {
	Items      []*IdsecARSAccessRequest `json:"items" mapstructure:"items" desc:"Access requests in this page"`
	Count      int                      `json:"count" mapstructure:"count" desc:"Count of items returned post filter / pagination"`
	TotalCount int                      `json:"total_count" mapstructure:"total_count" desc:"Overall items that exist"`
}
