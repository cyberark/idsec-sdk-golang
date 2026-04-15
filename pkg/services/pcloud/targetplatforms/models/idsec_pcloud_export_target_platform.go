package models

// IdsecPCloudExportTargetPlatform represents the details required to export a target platform.
type IdsecPCloudExportTargetPlatform struct {
	TargetPlatformID int    `json:"target_platform_id" mapstructure:"target_platform_id" desc:"ID of the platform to export (export of the platform's zip file)" flag:"target-platform-id" validate:"required"`
	OutputFolder     string `json:"output_folder" mapstructure:"output_folder" desc:"Output folder path to store the target platform's zip file" flag:"output-folder" validate:"required"`
}
