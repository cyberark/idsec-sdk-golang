package models

// IdsecSIADBMysqlExecution defines the structure for executing MySQL commands in the IdsecDBA context.
type IdsecSIADBMysqlExecution struct {
	IdsecSIADBBaseExecution `mapstructure:",squash"`
	MysqlPath             string `json:"mysql_path" mapstructure:"mysql_path" flag:"mysql-path" desc:"The path to the MySQL executable file." default:"mysql"`
}
