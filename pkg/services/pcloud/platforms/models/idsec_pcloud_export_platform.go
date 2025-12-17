package models

// IdsecPCloudExportPlatform represents the details required to export a platform.
type IdsecPCloudExportPlatform struct {
	PlatformID   string `json:"platform_id" mapstructure:"platform_id" desc:"ID of the platform to export its zip data" flag:"platform-id" validate:"required"`
	OutputFolder string `json:"output_folder" mapstructure:"output_folder" desc:"Output folder path to write the zipped platform data to" flag:"output-folder" validate:"required"`
}
