package models

// IdsecPCloudExportPlatform represents the details required to export a platform.
type IdsecPCloudExportPlatform struct {
	PlatformID   string `json:"platform_id" mapstructure:"platform_id" desc:"ID of the platform to export (export of the platform's zip file)" flag:"platform-id" validate:"required"`
	OutputFolder string `json:"output_folder" mapstructure:"output_folder" desc:"Output folder path to store the platform's exported zip file" flag:"output-folder" validate:"required"`
}
