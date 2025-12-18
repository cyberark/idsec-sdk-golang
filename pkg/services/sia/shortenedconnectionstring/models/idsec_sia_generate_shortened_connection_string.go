package models

// IdsecSIAGenerateShortenedConnectionString represents the model for generating a shortened connection string.
type IdsecSIAGenerateShortenedConnectionString struct {
	RawConnectionString string `json:"raw_connection_string" mapstructure:"raw_connection_string" flag:"raw-connection-string" desc:"The raw connection string to shorten." validate:"required"`
}
