package models

// IdsecUAPPolicyResultsResponse represents the response containing policy results.
type IdsecUAPPolicyResultsResponse struct {
	Results   []IdsecUAPCommonAccessPolicy `json:"results" mapstructure:"results" desc:"List of policies"`
	NextToken string                       `json:"next_token,omitempty" mapstructure:"next_token,omitempty" desc:"The token from the previous API response. To retrieve the next N results, use DS1_10;DS2_20. This means that the service will retrieve 10 results from DS_1 and 20 results from DS_2."`
	Total     int                          `json:"total" mapstructure:"total" desc:"Total number of access policies."`
}
