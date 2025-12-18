package models

import "strings"

// Possible IdsecUAPFilterOperator
const (
	IdsecUAPFilterOperatorEQ       = "eq"
	IdsecUAPFilterOperatorContains = "contains"
	IdsecUAPFilterOperatorOR       = "or"
	IdsecUAPFilterOperatorAND      = "and"
)

// IdsecUAPDefaultLimitSize defines the default limit size for UAP access policies.
const (
	IdsecUAPDefaultLimitSize = 50
)

// filterOperators maps field names to their corresponding filter operators.
var filterOperators = map[string]string{
	"locationType":   IdsecUAPFilterOperatorEQ,
	"policyType":     IdsecUAPFilterOperatorEQ,
	"targetCategory": IdsecUAPFilterOperatorEQ,
	"policyTags":     IdsecUAPFilterOperatorEQ,
	"status":         IdsecUAPFilterOperatorEQ,
	"identities":     IdsecUAPFilterOperatorContains,
}

// mapAliasToFieldName maps alias names to their corresponding field names.
var mapAliasToFieldName = map[string]string{
	"locationType":   "LocationType",
	"policyType":     "PolicyType",
	"targetCategory": "TargetCategory",
	"policyTags":     "PolicyTags",
	"status":         "Status",
	"identities":     "Identities",
}

// IdsecUAPGetQueryParams represents the query parameters for retrieving access policies.
type IdsecUAPGetQueryParams struct {
	Filter               string `json:"filter,omitempty" mapstructure:"filter,omitempty" flag:"filter" desc:"Filter query to retrieve access policies. Supported operations: eq (except Identities which supports only contains), or, and. If you want to query on the same field, use 'or' condition. Use the 'and' operation to filter on two fields or more. Supported field names: policyTags, identities, targetCategory, status, locationType."`
	ShowEditablePolicies bool   `json:"show_editable_policies,omitempty" mapstructure:"show_editable_policies,omitempty" flag:"show-editable-policies" desc:"Show editable policies"`
	Q                    string `json:"q,omitempty" mapstructure:"q,omitempty" flag:"q" desc:"Use this for a free text search on policy name and description."`
	NextToken            string `json:"next_token,omitempty" mapstructure:"next_token,omitempty" flag:"next-token" desc:"Token from the previous API response. To retrieve the next N results, use DS1_10;DS2_20. This means that the service will retrieve 10 results from DS_1 and 20 results from DS_2"`
	Limit                int    `json:"limit" mapstructure:"limit" flag:"limit" desc:"The maximum number of access policies to return. You can request up to 50 policies."`
}

// IdsecUAPFilters represents the filters for Access control policies.
type IdsecUAPFilters struct {
	LocationType         []string `json:"location_type,omitempty" mapstructure:"location_type,omitempty" flag:"location-type" desc:"List of location types by which to filter the policies"`
	TargetCategory       []string `json:"target_category,omitempty" mapstructure:"target_category,omitempty" flag:"target-category" desc:"List of target categories by which to filter the policies"`
	PolicyType           []string `json:"policy_type,omitempty" mapstructure:"policy_type,omitempty" flag:"policy-type" desc:"List of policy types by which to filter the policies"`
	PolicyTags           []string `json:"policy_tags,omitempty" mapstructure:"policy_tags,omitempty" flag:"policy-tags" desc:"List of policy tags by which to filter the policies"`
	Identities           []string `json:"identities,omitempty" mapstructure:"identities,omitempty" flag:"identities" desc:"List of identities by which to filter the policies"`
	Status               []string `json:"status,omitempty" mapstructure:"status,omitempty" flag:"status" desc:"List of policy statuses by which to filter the policies"`
	TextSearch           string   `json:"text_search,omitempty" mapstructure:"text_search,omitempty" flag:"text-search" desc:"Text search filter to apply on policy names and descriptions"`
	ShowEditablePolicies bool     `json:"show_editable_policies,omitempty" mapstructure:"show_editable_policies,omitempty" flag:"show-editable-policies" desc:"Whether or not to show editable policies" default:"true"`
	MaxPages             int      `json:"max_pages" mapstructure:"max_pages" flag:"max-pages" desc:"The maximum number of pages for pagination, Default: 1000000" default:"1000000"`
}

// NewIdsecUAPFilters initializes a new instance of IdsecUAPFilters with default values.
func NewIdsecUAPFilters() *IdsecUAPFilters {
	return &IdsecUAPFilters{
		LocationType:         []string{},
		TargetCategory:       []string{},
		PolicyType:           []string{},
		PolicyTags:           []string{},
		Identities:           []string{},
		Status:               []string{},
		TextSearch:           "",
		ShowEditablePolicies: true,
		MaxPages:             1000000,
	}
}

// BuildFilterQueryFromFilters constructs a filter query string from the provided filters.
func (filters *IdsecUAPFilters) BuildFilterQueryFromFilters() string {
	var clauses []string

	for fieldName, operator := range filterOperators {
		alias := mapAliasToFieldName[fieldName]
		var values []string

		switch alias {
		case "LocationType":
			values = filters.LocationType
		case "PolicyType":
			values = filters.PolicyType
		case "TargetCategory":
			values = filters.TargetCategory
		case "PolicyTags":
			values = filters.PolicyTags
		case "Status":
			values = filters.Status
		case "Identities":
			values = filters.Identities
		}

		if len(values) > 0 {
			var itemClauses []string
			for _, v := range values {
				itemClauses = append(itemClauses, "("+fieldName+" "+operator+" '"+v+"')")
			}
			joined := strings.Join(itemClauses, " "+IdsecUAPFilterOperatorOR+" ")
			if len(itemClauses) > 1 {
				clauses = append(clauses, "("+joined+")")
			} else {
				clauses = append(clauses, joined)
			}
		}
	}

	if len(clauses) > 1 {
		return "(" + strings.Join(clauses, " and ") + ")"
	} else if len(clauses) == 1 {
		return clauses[0]
	}
	return ""
}

// IdsecUAPGetAccessPoliciesRequest represents the request to get access policies.
type IdsecUAPGetAccessPoliciesRequest struct {
	Filters   *IdsecUAPFilters `json:"filters,omitempty" mapstructure:"filters,omitempty" flag:"filters" desc:"The filter query to apply on the policies"`
	Limit     int              `json:"limit" mapstructure:"limit" flag:"limit" desc:"The maximum number of policies to return in the response; Default: 50" default:"50"`
	NextToken string           `json:"next_token,omitempty" mapstructure:"next_token,omitempty" flag:"next-token" desc:"The next token for pagination"`
}

// BuildGetQueryParams constructs the query parameters for retrieving access policies.
func (request *IdsecUAPGetAccessPoliciesRequest) BuildGetQueryParams() IdsecUAPGetQueryParams {
	queryParams := IdsecUAPGetQueryParams{
		Limit: request.Limit,
	}
	if queryParams.Limit <= 0 {
		queryParams.Limit = IdsecUAPDefaultLimitSize
	}

	if request.Filters == nil {
		return queryParams
	}

	localFilters := request.Filters

	if localFilters.TextSearch != "" {
		queryParams.Q = localFilters.TextSearch
	}

	filterQuery := localFilters.BuildFilterQueryFromFilters()
	if filterQuery != "" {
		queryParams.Filter = filterQuery
	}

	if request.NextToken != "" {
		queryParams.NextToken = request.NextToken
	}

	queryParams.ShowEditablePolicies = localFilters.ShowEditablePolicies

	return queryParams
}
