package models

// IdsecSecHubUpdateConfiguration represnets the response when updating configuraiton settings.
type IdsecSecHubUpdateConfiguration struct {
	SyncSettings IdsecSecHubSyncSettings `json:"sync_settings" mapstructure:"sync_settings" desc:"Sync Settings for Secrets Hub" flag:"sync-settings" validate:"required"`
}
