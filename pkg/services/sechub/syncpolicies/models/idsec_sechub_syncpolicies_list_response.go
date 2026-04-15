package models

// IdsecSecHubSyncPoliciesListResponse represents the paginated API response for listing sync policies.
// It maps directly to the response body returned by the list endpoint, allowing it to be
// decoded in a single step via validateAndDecodeHTTPResponse.
type IdsecSecHubSyncPoliciesListResponse struct {
	Policies []*IdsecSecHubPolicy `json:"policies" mapstructure:"policies"`
	NextLink string               `json:"next_link,omitempty" mapstructure:"next_link,omitempty"`
}
