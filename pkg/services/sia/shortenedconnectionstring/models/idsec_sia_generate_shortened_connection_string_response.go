package models

// IdsecSIAGenerateShortenedConnectionStringResponse represents the response for generating a shortened connection string.
type IdsecSIAGenerateShortenedConnectionStringResponse struct {
	ShortenedConnectionString string `json:"connection_string_alias" mapstructure:"connection_string_alias" flag:"connection-string-alias" desc:"The generated shortened connection string." validate:"required"`
	RawConnectionString       string `json:"raw_connection_string" mapstructure:"raw_connection_string" flag:"raw-connection-string" desc:"The original raw connection string from the request." validate:"required"`
}
