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

// Deprecation describes why an action is deprecated and what users should use instead.
//
// Deprecation is consumed by every Idsec surface that builds itself from a
// service action definition (CLI, Terraform provider, generated docs, etc.),
// so the same metadata produces consistent warnings and help/markdown output.
type Deprecation struct {
	Message     string `mapstructure:"message,omitempty" json:"message,omitempty" desc:"Human readable explanation of why the action is deprecated"`
	Replacement string `mapstructure:"replacement,omitempty" json:"replacement,omitempty" desc:"Action or path users should migrate to"`
}

// IsZero reports whether the deprecation has no user-facing content.
func (d *Deprecation) IsZero() bool {
	return d == nil || (d.Message == "" && d.Replacement == "")
}

// CLIFormatter is implemented by types that want to control how a service action's
// result is displayed in the CLI instead of the default JSON output.
// Format receives the raw return value from the service method (e.g. *IdsecSIADoctorReport)
// and must return a ready-to-print string, including any ANSI colour codes.
type CLIFormatter interface {
	Format(result any) string
}

// IdsecServiceCLIActionDefinition is a struct that defines the structure of an action in the Idsec CLI.
type IdsecServiceCLIActionDefinition struct {
	IdsecServiceBaseActionDefinition `mapstructure:",squash"`
	ActionAliases                    []string                           `mapstructure:"action_aliases,omitempty" json:"action_aliases,omitempty" desc:"Action aliases to be used in the cli commands"`
	Defaults                         map[string]map[string]interface{}  `mapstructure:"defaults,omitempty" json:"defaults,omitempty" desc:"Defaults for the action schemas parameters"`
	AsyncActions                     []string                           `mapstructure:"async_actions,omitempty" json:"async_actions,omitempty" desc:"List of async actions as part of the schemas"`
	Subactions                       []*IdsecServiceCLIActionDefinition `mapstructure:"subactions,omitempty" json:"subactions,omitempty" desc:"Subactions to this action"`
	Deprecation                      *Deprecation                       `mapstructure:"deprecation,omitempty" json:"deprecation,omitempty" desc:"Deprecation metadata for the action tree node"`
	// Formatters maps action names (matching keys in Schemas) to a CLIFormatter
	// that controls how the result is rendered in the terminal.
	// When nil or when the action name has no entry, the default JSON output is used.
	Formatters map[string]CLIFormatter `mapstructure:"-" json:"-"`
}

// ActionType returns the type of action, which is CLI in this case.
func (a *IdsecServiceCLIActionDefinition) ActionType() IdsecServiceActionType {
	return IdsecServiceActionTypeCLI
}
