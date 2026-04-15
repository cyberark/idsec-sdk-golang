package models

// IdsecCmgrPoolsCommonFilter is a struct representing the common filter for pools in the Idsec CMGR service.
type IdsecCmgrPoolsCommonFilter struct {
	Projection string `json:"projection" mapstructure:"projection" flag:"projection" desc:"The type of projection for the response." default:"BASIC" choices:"BASIC,EXTENDED"`
	Sort       string `json:"sort,omitempty" mapstructure:"sort,omitempty" flag:"sort" desc:"The sort parameter."`
	Filter     string `json:"filter,omitempty" mapstructure:"filter,omitempty" flag:"filter" desc:"The filter parameters."`
	Order      string `json:"order,omitempty" mapstructure:"order,omitempty" flag:"order" desc:"The sort order of the response." choices:"ASC,DESC" default:"ASC"`
	PageSize   int    `json:"page_size,omitempty" mapstructure:"page_size,omitempty" flag:"page-size" desc:"The size of the page."`
}

// IdsecCmgrBulkResponse is a struct representing the response of a bulk request in the Idsec CMGR service.
type IdsecCmgrBulkResponse struct {
	Body       map[string]interface{} `json:"body,omitempty" mapstructure:"body,omitempty" flag:"body" desc:"The response body of the request."`
	StatusCode int                    `json:"status_code" mapstructure:"status_code" flag:"status-code" desc:"The status code of the response."`
}

// IdsecCmgrBulkResponses is a struct representing the responses of a bulk request in the Idsec CMGR service.
type IdsecCmgrBulkResponses struct {
	Responses map[string]IdsecCmgrBulkResponse `json:"responses" mapstructure:"responses" flag:"responses" desc:"The responses of the bulk request."`
}
