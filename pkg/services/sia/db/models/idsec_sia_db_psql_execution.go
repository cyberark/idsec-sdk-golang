package models

// IdsecSIADBPsqlExecution defines the structure for executing PostgreSQL commands in the IdsecDBA context.
type IdsecSIADBPsqlExecution struct {
	IdsecSIADBBaseExecution `mapstructure:",squash"`
	PsqlPath                string `json:"psql_path" mapstructure:"psql_path" flag:"psql-path" desc:"Path to the psql executable" default:"psql"`
}
