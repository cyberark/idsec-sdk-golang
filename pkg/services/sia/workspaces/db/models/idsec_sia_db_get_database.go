package models

// IdsecSIADBGetDatabase represents the request to retrieve a database in a workspace.
type IdsecSIADBGetDatabase struct {
	ID   int    `json:"id,omitempty" mapstructure:"id,omitempty" flag:"id" desc:"Database id to get"`
	Name string `json:"name,omitempty" mapstructure:"name,omitempty" flag:"name" desc:"Database name to get"`
}

// IdsecSIADBGetDatabaseTarget represents the request to retrieve a database in a workspace by the database-onboarding new API
type IdsecSIADBGetDatabaseTarget struct {
	ID   string `json:"id,omitempty" mapstructure:"id,omitempty" flag:"id" desc:"Database id to get"`
	Name string `json:"name,omitempty" mapstructure:"name,omitempty" flag:"name" desc:"Database name to get"`
}
