package models

// IdsecARSAccessRequestsStats represents statistics about access requests.
type IdsecARSAccessRequestsStats struct {
	RequestsCount           int                                 `json:"requests_count" mapstructure:"requests_count" desc:"Overall access requests count"`
	RequestsCountByCategory map[string]int                      `json:"requests_count_by_category" mapstructure:"requests_count_by_category" desc:"Access requests count by category"`
	RequestsCountByState    map[IdsecARSAccessRequestState]int  `json:"requests_count_by_state" mapstructure:"requests_count_by_state" desc:"Access requests count by state"`
	RequestsCountByResult   map[IdsecARSAccessRequestResult]int `json:"requests_count_by_result" mapstructure:"requests_count_by_result" desc:"Access requests count by result"`
}
