package models

// IdsecSIADBSqlcmdExecution defines the structure for executing SQLCMD commands in the IdsecDBA context.
type IdsecSIADBSqlcmdExecution struct {
	IdsecSIADBBaseExecution `mapstructure:",squash"`
	SqlcmdPath            string `json:"sqlcmd_path" mapstructure:"sqlcmd_path" flag:"sqlcmd-path" desc:"The path to the SQLCMD executable file." default:"sqlcmd"`
}
