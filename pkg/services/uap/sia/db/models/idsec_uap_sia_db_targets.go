package models

// IdsecUAPSIADBTargets represents a collection of database instance targets in the UAP SIA DB.
type IdsecUAPSIADBTargets struct {
	Instances []IdsecUAPSIADBInstanceTarget `json:"instances" mapstructure:"instances" flag:"instances" desc:"The list of database instance targets." validate:"min=1,max=1000"`
}
