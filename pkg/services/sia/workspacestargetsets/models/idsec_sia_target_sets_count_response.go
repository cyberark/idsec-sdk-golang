package models

// IdsecSIATargetSetsCountResponse represents the response from counting target sets.
//
// This model provides an efficient way to get the count of target sets
// without fetching all the data.
//
// Fields:
//   - Count: The number of target sets matching the filter criteria
//
// Example:
//
//	response := &models.IdsecSIATargetSetsCountResponse{
//	    Count: 42,
//	}
type IdsecSIATargetSetsCountResponse struct {
	// Count is the total number of target sets matching the query.
	Count int `json:"count" mapstructure:"count"`
}
