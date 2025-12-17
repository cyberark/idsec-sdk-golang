package models

// IdsecSIADBSqlcmdExecution defines the structure for executing SQLCMD commands in the IdsecDBA context.
type IdsecSIADBSqlcmdExecution struct {
	IdsecSIADBBaseExecution `mapstructure:",squash"`
	SqlcmdPath              string `json:"sqlcmd_path" mapstructure:"sqlcmd_path" flag:"sqlcmd-path" desc:"Path to the sqlcmd executable" default:"sqlcmd"`
}
