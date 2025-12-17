package models

// IdsecSIAListTargetSetsOptions defines optional parameters for listing target sets.
//
// This model supports server-side pagination and filtering capabilities
// provided by the Target Sets API.
//
// Parameters:
//   - B64StartKey: Pagination token from previous response's b64_last_evaluated_key
//   - Name: Wildcard pattern to filter target sets by name (server-side)
//   - StrongAccountID: Filter target sets by associated strong account ID
//
// All fields are optional. If not provided, the API returns all target sets
// without filtering.
//
// Example:
//
//	options := &targetsetsmodels.IdsecSIAListTargetSetsOptions{
//	    Name:           "prod-*",
//	    StrongAccountID: "account-123",
//	}
type IdsecSIAListTargetSetsOptions struct {
	// B64StartKey is the pagination token for retrieving the next page of results.
	// Use the value from b64_last_evaluated_key in the previous response.
	B64StartKey *string `json:"b64_start_key,omitempty" mapstructure:"b64_start_key,omitempty" desc:"Pagination token from previous response for retrieving next page"`

	// Name is a wildcard pattern to filter target sets by name on the server side.
	Name *string `json:"name,omitempty" mapstructure:"name,omitempty" desc:"Wildcard pattern to filter target sets by name (e.g., 'prod-*')"`

	// StrongAccountID filters target sets by their associated strong account ID.
	StrongAccountID *string `json:"strong_account_id,omitempty" mapstructure:"strong_account_id,omitempty" desc:"Filter target sets by associated strong account ID"`
}
