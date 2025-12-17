package models

// IdsecSecHubScanMetadata represents the metadata for a scan.
type IdsecSecHubScanMetadata struct {
	StoreID string `json:"store_id" mapstructure:"store_id" flag:"store-id" desc:"Store ID associated with the scan"`
}

// IdsecSecHubScan represents a single scan in the Secrets Hub.
type IdsecSecHubScan struct {
	ID         string                  `json:"id,omitempty" mapstructure:"id,omitempty" flag:"id" desc:"Scan ID"`
	Metadata   IdsecSecHubScanMetadata `json:"metadata,omitempty" mapstructure:"metadata,omitempty" flag:"metadata" desc:"Scan metadata as JSON string"`
	Status     string                  `json:"status,omitempty" mapstructure:"status,omitempty" flag:"status" desc:"Scan status"`
	Message    string                  `json:"message,omitempty" mapstructure:"message" flag:"message" desc:"Scan message"`
	StartedAt  string                  `json:"started_at,omitempty" mapstructure:"started_at,omitempty" flag:"started-at" desc:"Scan start time"`
	FinishedAt string                  `json:"finished_at,omitempty" mapstructure:"finished_at,omitempty" flag:"finished-at" desc:"Scan finish time"`
	CreatedBy  string                  `json:"created_by,omitempty" mapstructure:"created_by,omitempty" flag:"created-by" desc:"Creator of the scan"`
}

// IdsecSecHubGetScans represents the response for getting scans.
type IdsecSecHubGetScans struct {
	Count int               `json:"count" mapstructure:"count" flag:"count" desc:"Total number of scans"`
	Scans []IdsecSecHubScan `json:"scans" mapstructure:"scans" flag:"scans" desc:"List of scans"`
}
