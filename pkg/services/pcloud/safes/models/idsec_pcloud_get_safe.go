package models

// IdsecPCloudGetSafe represents the details required to get a safe's details.
type IdsecPCloudGetSafe struct {
	SafeID   string `json:"safe_id" mapstructure:"safe_id" desc:"The URL encoding of the Safe name for retrieving the Safe's details. For special characters, enter the encoding of the special character. For example, enter %20 to represent a space" flag:"safe-id"`
	SafeName string `json:"safe_name" mapstructure:"safe_name" desc:"The name of the Safe for retrieving the Safe's details" flag:"safe-name"`
}
