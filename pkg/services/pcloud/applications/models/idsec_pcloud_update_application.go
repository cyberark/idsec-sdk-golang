package models

// IdsecPCloudUpdateApplication represents the model for updating a pCloud application.
type IdsecPCloudUpdateApplication struct {
	IdsecPCloudCreateApplication `mapstructure:",squash"`
}
