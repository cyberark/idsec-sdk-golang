package models

// IdsecSecHubScanStats represents the response when getting scan statistics from SecHub.
type IdsecSecHubScanStats struct {
	ScansCount          int            `json:"scans_count" mapstructure:"scans_count" desc:"Overall scans count"`
	ScansCountByCreator map[string]int `json:"scans_count_by_creator" mapstructure:"scans_count_by_creator" desc:"Scans count by creator"`
}
