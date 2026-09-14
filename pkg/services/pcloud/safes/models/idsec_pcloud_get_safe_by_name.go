package models

// IdsecPCloudGetSafeByName represents the details required to get a safe by its name.
type IdsecPCloudGetSafeByName struct {
	SafeName string `json:"safe_name" mapstructure:"safe_name" desc:"The name of the Safe to retrieve" flag:"safe-name" validate:"required"`
}
