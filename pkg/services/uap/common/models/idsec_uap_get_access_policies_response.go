package models

// IdsecUAPPolicyResultsResponse represents the response containing policy results.
type IdsecUAPPolicyResultsResponse struct {
	Results   []IdsecUAPCommonAccessPolicy `json:"results" mapstructure:"results" desc:"List of policies"`
	NextToken string                       `json:"next_token,omitempty" mapstructure:"next_token,omitempty" desc:"Token for the next page of results"`
	Total     int                          `json:"total" mapstructure:"total" desc:"Total number of policies available"`
}
