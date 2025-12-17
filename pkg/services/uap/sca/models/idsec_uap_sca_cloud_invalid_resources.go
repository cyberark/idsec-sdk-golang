package models

// Possible values for IdsecUAPSCACloudInvalidWorkspace status.
const (
	StatusRemoved   string = "REMOVED"
	StatusSuspended string = "SUSPENDED"
)

// IdsecUAPSCACloudInvalidWorkspace represents an invalid workspace.
type IdsecUAPSCACloudInvalidWorkspace struct {
	ID     string `json:"id" mapstructure:"id" flag:"id" desc:"Resource ID"`
	Status string `json:"status" mapstructure:"status" flag:"status" desc:"Workspace status" choices:"REMOVED,SUSPENDED"`
}

// IdsecUAPSCACloudInvalidRole represents an invalid role.
type IdsecUAPSCACloudInvalidRole struct {
	ID string `json:"id" mapstructure:"id" flag:"id" desc:"Invalid role ID"`
}

// IdsecUAPSCACloudInvalidWebapp represents an invalid webapp.
type IdsecUAPSCACloudInvalidWebapp struct {
	ID string `json:"id" mapstructure:"id" flag:"id" desc:"Invalid webapp ID"`
}

// IdsecUAPSCACloudInvalidResources represents a collection of invalid resources.
type IdsecUAPSCACloudInvalidResources struct {
	Workspaces []IdsecUAPSCACloudInvalidWorkspace `json:"workspaces,omitempty" mapstructure:"workspaces,omitempty" flag:"workspaces" desc:"List of invalid workspaces"`
	Roles      []IdsecUAPSCACloudInvalidRole      `json:"roles,omitempty" mapstructure:"roles,omitempty" flag:"roles" desc:"List of invalid roles"`
	Webapps    []IdsecUAPSCACloudInvalidWebapp    `json:"webapps,omitempty" mapstructure:"webapps,omitempty" flag:"webapps" desc:"List of invalid webapps"`
}
