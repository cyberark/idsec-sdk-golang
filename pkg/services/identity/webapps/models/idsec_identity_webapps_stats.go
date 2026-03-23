package models

// IdsecIdentityWebappsStats represents the statistics of identity webapps.
type IdsecIdentityWebappsStats struct {
	AppsCount           int            `json:"apps_count" mapstructure:"apps_count" flag:"apps-count" desc:"Total number of webapps" validate:"required"`
	AppsCountByType     map[string]int `json:"apps_count_by_type" mapstructure:"apps_count_by_type" flag:"apps-count-by-type" desc:"Number of webapps by type" validate:"required"`
	AppsCountByCategory map[string]int `json:"apps_count_by_category" mapstructure:"apps_count_by_category" flag:"apps-count-by-category" desc:"Number of webapps by category" validate:"required"`
}
