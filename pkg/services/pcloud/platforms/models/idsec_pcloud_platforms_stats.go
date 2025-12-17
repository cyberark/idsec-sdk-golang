package models

// IdsecPCloudPlatformsStats represents the statistics of platforms.
type IdsecPCloudPlatformsStats struct {
	PlatformsCount       int            `json:"platforms_count" mapstructure:"platforms_count" desc:"Overall platforms amount" flag:"platforms-count"`
	PlatformsCountByType map[string]int `json:"platforms_count_by_type" mapstructure:"platforms_count_by_type" desc:"Platforms amount by type" flag:"platforms-count-by-type"`
}
