package models

// IdsecSIAListTargetSetsResponse represents the response from listing target sets.
//
// This model includes both the target sets data and pagination information
// for handling large result sets efficiently.
//
// Fields:
//   - TargetSets: Array of target set objects returned from the API
//   - B64LastEvaluatedKey: Pagination token for retrieving the next page (nil if no more pages)
//
// Example:
//
//	response := &models.IdsecSIAListTargetSetsResponse{
//	    TargetSets: []*models.IdsecSIATargetSet{...},
//	    B64LastEvaluatedKey: strPtr("next-page-token"),
//	}
type IdsecSIAListTargetSetsResponse struct {
	// TargetSets is the array of target sets returned from the query.
	TargetSets []*IdsecSIATargetSet `json:"target_sets" mapstructure:"target_sets"`

	// B64LastEvaluatedKey is the pagination token for fetching the next page.
	// If nil, there are no more pages to retrieve.
	B64LastEvaluatedKey *string `json:"b64_last_evaluated_key,omitempty" mapstructure:"b64_last_evaluated_key,omitempty"`
}
