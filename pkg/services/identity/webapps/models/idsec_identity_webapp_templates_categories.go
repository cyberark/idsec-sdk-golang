package models

// IdsecIdentityWebappTemplatesCategories represents the response body for fetching webapp template categories.
type IdsecIdentityWebappTemplatesCategories struct {
	Categories []string `json:"categories" mapstructure:"categories" flag:"categories" desc:"List of webapp template categories" validate:"required"`
}
