package models

// IdsecPCloudGetApplication represents the model for getting a pCloud application.
type IdsecPCloudGetApplication struct {
	AppID string `json:"app_id" mapstructure:"app_id" flag:"app-id" desc:"The application ID"`
}
