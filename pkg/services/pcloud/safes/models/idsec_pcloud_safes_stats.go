package models

// IdsecPCloudSafesStats represents statistics about safes.
type IdsecPCloudSafesStats struct {
	SafesCount           int            `json:"safes_count" mapstructure:"safes_count" desc:"Number of Safes"`
	SafesCountByLocation map[string]int `json:"safes_count_by_location" mapstructure:"safes_count_by_location" desc:"Number of Safes per location"`
	SafesCountByCreator  map[string]int `json:"safes_count_by_creator" mapstructure:"safes_count_by_creator" desc:"Number of Safes per creator"`
}
