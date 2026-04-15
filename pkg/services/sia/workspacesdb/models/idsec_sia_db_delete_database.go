package models

// IdsecSIADBDeleteDatabase represents the request to delete a database.
type IdsecSIADBDeleteDatabase struct {
	ID   int    `json:"id,omitempty" mapstructure:"id,omitempty" flag:"id" desc:"The database ID to delete."`
	Name string `json:"name,omitempty" mapstructure:"name,omitempty" flag:"name" desc:"The database name to delete."`
}

// IdsecSIADBDeleteDatabaseTarget represents the request to delete a database by the database-onboarding new API
type IdsecSIADBDeleteDatabaseTarget struct {
	ID   string `json:"id,omitempty" mapstructure:"id,omitempty" flag:"id" desc:"The database ID to get."`
	Name string `json:"name,omitempty" mapstructure:"name,omitempty" flag:"name" desc:"The database name to get."`
}
