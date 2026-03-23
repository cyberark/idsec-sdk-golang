package models

// IdsecPCloudDeleteApplication represents the model for deleting a pCloud application.
type IdsecPCloudDeleteApplication struct {
	AppID string `json:"app_id" mapstructure:"app_id" flag:"app-id" desc:"The application ID"`
}
