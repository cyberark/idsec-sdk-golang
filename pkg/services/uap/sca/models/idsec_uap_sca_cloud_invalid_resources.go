package models

// Possible values for IdsecUAPSCACloudInvalidWorkspace status.
const (
	StatusRemoved   string = "REMOVED"
	StatusSuspended string = "SUSPENDED"
)

// IdsecUAPSCACloudInvalidWorkspace represents an invalid workspace.
type IdsecUAPSCACloudInvalidWorkspace struct {
	ID     string `json:"id" validate:"required" mapstructure:"id" flag:"id" desc:"Resource ID"`
	Status string `json:"status" validate:"required" mapstructure:"status" flag:"status" desc:"The status of the workspace. Valid values: REMOVED, SUSPENDED" choices:"REMOVED,SUSPENDED"`
}

// IdsecUAPSCACloudInvalidRole represents an invalid role.
type IdsecUAPSCACloudInvalidRole struct {
	ID string `json:"id" validate:"required" mapstructure:"id" flag:"id" desc:"Invalid role ID. For example: arn:aws:iam::123456789:role/FullAccessToDevelopers"`
}

// IdsecUAPSCACloudInvalidWebapp represents an invalid webapp.
type IdsecUAPSCACloudInvalidWebapp struct {
	ID string `json:"id" validate:"required" mapstructure:"id" flag:"id" desc:"Invalid web app ID"`
}

// IdsecUAPSCACloudInvalidResources represents a collection of invalid resources.
type IdsecUAPSCACloudInvalidResources struct {
	Workspaces []IdsecUAPSCACloudInvalidWorkspace `json:"workspaces,omitempty" mapstructure:"workspaces,omitempty" flag:"workspaces" desc:"The invalid targets in the policy"`
	Roles      []IdsecUAPSCACloudInvalidRole      `json:"roles,omitempty" mapstructure:"roles,omitempty" flag:"roles" desc:"The invalid roles in the policy"`
	Webapps    []IdsecUAPSCACloudInvalidWebapp    `json:"webapps,omitempty" mapstructure:"webapps,omitempty" flag:"webapps" desc:"The invalid web apps of the policy"`
}
