package actions

// IdsecServiceActionType defines the type of action for an Idsec service, such as CLI.
type IdsecServiceActionType string

// Constants for IdsecServiceActionType
const (
	IdsecServiceActionTypeCLI IdsecServiceActionType = "cli"
)

// IdsecServiceActionDefinition is an interface that defines the structure of an action for an Idsec service.
type IdsecServiceActionDefinition interface {
	ActionType() IdsecServiceActionType
	ActionDefinitionName() string
	IsEnabled() bool
}

// IdsecServiceBaseActionDefinition is a struct that defines the base structure of an action using Idsec SDK
type IdsecServiceBaseActionDefinition struct {
	ActionName        string                 `mapstructure:"action_name" json:"action_name" desc:"Action name to be used in the cli commands"`
	Enabled           *bool                  `mapstructure:"enabled,omitempty" json:"enabled,omitempty" desc:"Whether the action is enabled for registration"`
	ActionDescription string                 `mapstructure:"action_description,omitempty" json:"action_description,omitempty" desc:"Action description to be used in the cli commands"`
	ActionVersion     int64                  `mapstructure:"action_version,omitempty" json:"action_version,omitempty" desc:"Action version to be used in the cli commands"`
	Schemas           map[string]interface{} `mapstructure:"schemas,omitempty" json:"schemas,omitempty" desc:"Schemas for different cli actions for the definition"`
}

// ActionDefinitionName returns the name of the action definition.
func (a *IdsecServiceBaseActionDefinition) ActionDefinitionName() string {
	return a.ActionName
}

// IsEnabled returns whether the action is enabled for registration.
// Returns true if Enabled is nil (default) or explicitly set to true.
func (a *IdsecServiceBaseActionDefinition) IsEnabled() bool {
	return a.Enabled == nil || *a.Enabled
}

// IdsecServiceCLIActionDefinition is a struct that defines the structure of an action in the Idsec CLI.
type IdsecServiceCLIActionDefinition struct {
	IdsecServiceBaseActionDefinition `mapstructure:",squash"`
	ActionAliases                    []string                           `mapstructure:"action_aliases,omitempty" json:"action_aliases,omitempty" desc:"Action aliases to be used in the cli commands"`
	Defaults                         map[string]map[string]interface{}  `mapstructure:"defaults,omitempty" json:"defaults,omitempty" desc:"Defaults for the action schemas parameters"`
	AsyncActions                     []string                           `mapstructure:"async_actions,omitempty" json:"async_actions,omitempty" desc:"List of async actions as part of the schemas"`
	Subactions                       []*IdsecServiceCLIActionDefinition `mapstructure:"subactions,omitempty" json:"subactions,omitempty" desc:"Subactions to this action"`
}

// ActionType returns the type of action, which is CLI in this case.
func (a *IdsecServiceCLIActionDefinition) ActionType() IdsecServiceActionType {
	return IdsecServiceActionTypeCLI
}
