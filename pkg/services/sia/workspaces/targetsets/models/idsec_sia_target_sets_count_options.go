package models

// IdsecSIATargetSetsCountOptions defines optional parameters for counting target sets.
//
// This model supports server-side filtering for efficient counting without
// fetching all target set data.
//
// Parameters:
//   - B64StartKey: Pagination token (typically not used for count, but supported by API)
//   - Name: Wildcard pattern to filter target sets by name before counting
//   - StrongAccountID: Filter target sets by strong account ID before counting
//
// All fields are optional. If not provided, counts all target sets.
//
// Example:
//
//	options := &models.IdsecSIATargetSetsCountOptions{
//	    Name:           "prod-*",
//	    StrongAccountID: strPtr("account-123"),
//	}
//	count, err := service.TargetSetsCount(options)
type IdsecSIATargetSetsCountOptions struct {
	// B64StartKey is the pagination token (typically not needed for count queries).
	B64StartKey *string `json:"b64_start_key,omitempty" mapstructure:"b64_start_key,omitempty" desc:"The pagination token (typically not needed for count queries)."`

	// Name is a wildcard pattern to filter target sets by name before counting.
	Name *string `json:"name,omitempty" mapstructure:"name,omitempty" desc:"The wildcard pattern used to filter target sets by name before counting. For example, 'prod-*'."`

	// StrongAccountID filters target sets by their associated strong account ID before counting.
	StrongAccountID *string `json:"strong_account_id,omitempty" mapstructure:"strong_account_id,omitempty" desc:"The associated strong account ID by which to filter the target sets before counting."`
}
