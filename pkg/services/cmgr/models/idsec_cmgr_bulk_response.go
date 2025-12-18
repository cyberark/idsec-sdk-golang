package models

// IdsecCmgrBulkResponse is a struct representing the response of a bulk request in the Idsec CMGR service.
type IdsecCmgrBulkResponse struct {
	Body       map[string]interface{} `json:"body,omitempty" mapstructure:"body,omitempty" flag:"body" desc:"The response body of the request."`
	StatusCode int                    `json:"status_code" mapstructure:"status_code" flag:"status-code" desc:"The status code of the response."`
}

// IdsecCmgrBulkResponses is a struct representing the responses of a bulk request in the Ark CMGR service.
type IdsecCmgrBulkResponses struct {
	Responses map[string]IdsecCmgrBulkResponse `json:"responses" mapstructure:"responses" flag:"responses" desc:"The responses of the bulk request."`
}
