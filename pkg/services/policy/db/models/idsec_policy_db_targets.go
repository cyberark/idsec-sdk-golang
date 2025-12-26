package models

// IdsecPolicyDBTargets represents a collection of database instance targets in the Infrastructure DB.
type IdsecPolicyDBTargets struct {
	Instances []IdsecPolicyDBInstanceTarget `json:"instances" mapstructure:"instances" flag:"instances" desc:"The list of database instance targets." validate:"min=1,max=1000"`
}
