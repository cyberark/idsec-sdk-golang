package models

// IdsecPCloudTargetPlatformsFilter represents the filter criteria for listing target platforms.
type IdsecPCloudTargetPlatformsFilter struct {
	Name               string `json:"name,omitempty" mapstructure:"name" desc:"Name wildcard to filter on" flag:"name"`
	PlatformID         string `json:"platform_id,omitempty" mapstructure:"platform_id" desc:"Platform id wildcard to filter on" flag:"platform-id"`
	Active             bool   `json:"active,omitempty" mapstructure:"active" desc:"Filter by active target platforms" flag:"active"`
	SystemType         string `json:"system_type,omitempty" mapstructure:"system_type" desc:"Filter by system type" flag:"system-type"`
	PeriodicVerify     bool   `json:"periodic_verify,omitempty" mapstructure:"periodic_verify" desc:"Filter by if periodic verify is on" flag:"periodic-verify"`
	ManualVerify       bool   `json:"manual_verify,omitempty" mapstructure:"manual_verify" desc:"Filter by if manual verify is on" flag:"manual-verify"`
	PeriodicChange     bool   `json:"periodic_change,omitempty" mapstructure:"periodic_change" desc:"Filter by if periodic change is on" flag:"periodic-change"`
	ManualChange       bool   `json:"manual_change,omitempty" mapstructure:"manual_change" desc:"Filter by if manual change is on" flag:"manual-change"`
	AutomaticReconcile bool   `json:"automatic_reconcile,omitempty" mapstructure:"automatic_reconcile" desc:"Filter by if automatic reconcile is on" flag:"automatic-reconcile"`
	ManualReconcile    bool   `json:"manual_reconcile,omitempty" mapstructure:"manual_reconcile" desc:"Filter by if manual reconcile is on" flag:"manual-reconcile"`
}
