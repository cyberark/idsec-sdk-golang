package models

// IdsecSecHubSetConfiguration represnets the response when updating configuraiton settings.
type IdsecSecHubSetConfiguration struct {
	SyncSettings IdsecSecHubSyncSettings `json:"sync_settings" mapstructure:"sync_settings" desc:"Sync Settings for Secrets Hub" flag:"sync-settings" validate:"required"`
}
