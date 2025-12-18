package models

// IdsecSIATargetSetsStats represents the statistics of target sets in a workspace.
type IdsecSIATargetSetsStats struct {
	TargetSetsCount              int            `json:"target_sets_count" mapstructure:"target_sets_count" flag:"target-sets-count" desc:"The total number of target sets." validate:"required"`
	TargetSetsCountPerSecretType map[string]int `json:"target_sets_count_per_secret_type" mapstructure:"target_sets_count_per_secret_type" flag:"target-sets-count-per-secret-type" desc:"The total number of target sets per Secret type." validate:"required"`
}
