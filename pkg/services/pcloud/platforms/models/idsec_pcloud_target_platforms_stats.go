package models

// IdsecPCloudTargetPlatformsStats represents the statistics of target platforms.
type IdsecPCloudTargetPlatformsStats struct {
	TargetPlatformsCount             int            `json:"target_platforms_count" mapstructure:"target_platforms_count" desc:"Overall target platforms amount" flag:"target-platforms-count"`
	ActiveTargetPlatformsCount       int            `json:"active_target_platforms_count" mapstructure:"active_target_platforms_count" desc:"Amount of active target platforms" flag:"active-target-platforms-count"`
	TargetPlatformsCountBySystemType map[string]int `json:"target_platforms_count_by_system_type" mapstructure:"target_platforms_count_by_system_type" desc:"Target platforms amount by system type" flag:"target-platforms-count-by-system-type"`
}
