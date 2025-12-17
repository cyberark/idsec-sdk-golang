package models

import (
	"fmt"
)

// Possible onboarding types.
// OPENAPI-CORRELATION: OnboardingType
const (
	Standard          = "standard"
	Programmatic      = "programmatic"
	TerraformProvider = "terraform_provider"
)

// Possible onboarding statuses.
// OPENAPI-CORRELATION: OnboardingStatus
const (
	Removing             = "Removing"
	DeployingResources   = "Deploying resources"
	WaitingForDeployment = "Waiting for deployment"
	WaitingForConsent    = "Waiting for consent"
	PartiallyAdded       = "Partially added"
	FailedToAdd          = "Failed to add"
	ServiceError         = "Service Error"
	CompletelyAdded      = "Completely added"
)

// Possible supported services.
// OPENAPI-CORRELATION: OnboardingSupportedServices
const (
	DPA        = "dpa"
	SCA        = "sca"
	SecretsHub = "secrets_hub"
	CDS        = "cds"
)

// IdsecCCEOnboardedService represents a service that has been onboarded.
// OPENAPI-CORRELATION: OnboardedService
type IdsecCCEOnboardedService struct {
	Name       string                    `json:"name" mapstructure:"name" choices:"dpa,sca,secrets_hub,cds" desc:"Service name identifier"`
	Status     string                    `json:"status" mapstructure:"status" choices:"Removing,Deploying resources,Waiting for deployment,Waiting for consent,Partially added,Failed to add,Service Error,Completely added" desc:"Onboarding status of the service"`
	Errors     []string                  `json:"errors" mapstructure:"errors" desc:"Any errors that occurred during onboarding"`
	Properties *[]IdsecCCEPropertyOutput `json:"properties,omitempty" mapstructure:"properties" desc:"Additional properties for the service"`
	Suspended  *bool                     `json:"suspended,omitempty" mapstructure:"suspended" desc:"Whether the service is suspended"`
}

// Deserialize fixes up union types in already-populated service data.
// The parent has already called mapstructure.Decode() to populate all regular fields.
func (o *IdsecCCEOnboardedService) Deserialize(data map[string]interface{}) error {
	// Properties already populated by parent's mapstructure.Decode()
	// Just fix up Value union types
	if o.Properties != nil {
		propsData, ok := data["properties"].([]interface{})
		if !ok {
			return nil
		}

		props := *o.Properties
		for i := range props {
			if i >= len(propsData) {
				break
			}
			if propMap, ok := propsData[i].(map[string]interface{}); ok {
				if valueData, ok := propMap["value"]; ok {
					if err := props[i].Value.Deserialize(valueData); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// Possible property names.
// OPENAPI-CORRELATION: PropertyName
const (
	CCEBrokenRole = "cce_broken_role"
	AzureDomain   = "azure_domain"
)

// IdsecCCEPropertyValue represents a property value union type.
// It can hold either a boolean value or a string value.
type IdsecCCEPropertyValue struct {
	BoolValue   *bool
	StringValue *string `desc:"Can contain regular strings or boolean values"`
}

// Serialize returns the raw value (bool or string) for serialization.
func (v *IdsecCCEPropertyValue) Serialize() (interface{}, error) {
	if v.BoolValue != nil {
		return *v.BoolValue, nil
	}
	if v.StringValue != nil {
		return *v.StringValue, nil
	}
	return nil, nil
}

// Deserialize populates the appropriate field based on the data type.
func (v *IdsecCCEPropertyValue) Deserialize(data interface{}) error {
	if data == nil {
		return nil
	}

	// Try boolean first
	if boolVal, ok := data.(bool); ok {
		v.BoolValue = &boolVal
		v.StringValue = nil
		return nil
	}

	// Try string
	if stringVal, ok := data.(string); ok {
		v.StringValue = &stringVal
		v.BoolValue = nil
		return nil
	}

	return fmt.Errorf("property value must be a boolean or string, got: %T", data)
}

// IdsecCCEPropertyOutput represents a property with a name and value.
// OPENAPI-CORRELATION: PropertyOutput
type IdsecCCEPropertyOutput struct {
	Name string `json:"name" mapstructure:"name" choices:"cce_broken_role,azure_domain"`
	// Note: mapstructure skips this field; it's populated manually by parent's Deserialize()
	Value IdsecCCEPropertyValue `json:"value" mapstructure:"-" desc:"Property value which can be a boolean or string"`
}

// IdsecCCEServiceInput represents a service to be onboarded with its resources.
// OPENAPI-CORRELATION: ServiceInput
type IdsecCCEServiceInput struct {
	ServiceName string                 `json:"serviceName" mapstructure:"service_name" choices:"dpa,sca,secrets_hub,cds" desc:"Name of the service to be onboarded"`
	Resources   map[string]interface{} `json:"resources" mapstructure:"resources" desc:"Service-specific resource configuration"`
}

// IdsecCCEServiceDto represents a service that has been deployed to a workspace.
// OPENAPI-CORRELATION: ServiceDto
type IdsecCCEServiceDto struct {
	Name           string            `json:"name" mapstructure:"name" choices:"dpa,sca,secrets_hub,cds" desc:"Service name identifier"`
	Version        string            `json:"version" mapstructure:"version" desc:"Service version number"`
	ServiceStatus  string            `json:"service_status" mapstructure:"service_status" choices:"Removing,Deploying resources,Waiting for deployment,Waiting for consent,Partially added,Failed to add,Service Error,Completely added" desc:"Current onboarding status of the service"`
	ErrorDetails   string            `json:"error_details,omitempty" mapstructure:"error_details" desc:"Detailed error information"`
	ServicesErrors []string          `json:"services_errors,omitempty" mapstructure:"services_errors" desc:"List of service errors"`
	Suspended      bool              `json:"suspended,omitempty" mapstructure:"suspended" desc:"Whether the service is suspended"`
	Resources      map[string]string `json:"resources,omitempty" mapstructure:"resources" desc:"Saved service resources for recovery purposes"`
}

// TfIdsecCCEWorkspace represents a workspace in the CCE system.
// OPENAPI-CORRELATION: WorkspaceOutput
type TfIdsecCCEWorkspace struct {
	// Key is the unique CCE onboarding ID for the workspace.
	Key string `json:"key" mapstructure:"key" desc:"Unique CCE onboarding ID for the workspace"`
	// Data contains the detailed workspace information including IDs, names, services, and status.
	Data TfIdsecCCEWorkspaceData `json:"data" mapstructure:"data" desc:"Detailed workspace information (IDs, names, services, status)"`
	// Leaf indicates whether this workspace is a leaf node (e.g., account) or can have children (e.g., organization/organization unit).
	Leaf bool `json:"leaf" mapstructure:"leaf" desc:"Indicates if workspace is leaf node (account) or can have children (organization/organization unit)"`
	// Path is the hierarchical path showing the workspace's location in the organizational structure.
	Path string `json:"path,omitempty" mapstructure:"path,omitempty" desc:"Hierarchical path in the organizational structure"`
	// ParentID is the CCE onboarding ID of the parent workspace (Organization or Organization Unit).
	ParentID string `json:"parent_id" mapstructure:"parent_id" desc:"CCE onboarding ID of parent workspace (Organization or Organization Unit)"`
}

// TfIdsecCCEWorkspaceData represents the data associated with a workspace.
// OPENAPI-CORRELATION: WorkspaceDataOutput
type TfIdsecCCEWorkspaceData struct {
	// ID is the CCE onboarding ID for the workspace.
	ID string `json:"id" mapstructure:"id" desc:"CCE onboarding ID for the workspace"`
	// PlatformID is the cloud provider's native identifier (e.g., AWS account ID "123456789012").
	PlatformID string `json:"platform_id" mapstructure:"platform_id" desc:"Cloud provider's native identifier (e.g., AWS account ID)"`
	// DisplayName is the human-readable name shown in the CCE UI.
	DisplayName string `json:"display_name" mapstructure:"display_name" desc:"Human-readable name shown in CCE UI"`
	// Type is the workspace type (e.g., aws_organization, aws_root, aws_ou, aws_account).
	Type string `json:"type" mapstructure:"type" desc:"Workspace type (e.g., aws_organization, aws_root, aws_ou, aws_account)"`
	// PlatformType is the cloud platform, which will be "AWS" for AWS workspaces.
	PlatformType string `json:"platform_type" mapstructure:"platform_type" desc:"Cloud platform (AWS)"`
	// OnboardingType indicates how the workspace was onboarded: "standard" (UI), "programmatic" (API), or "terraform_provider".
	OnboardingType string `json:"onboarding_type,omitempty" mapstructure:"onboarding_type" desc:"Onboarding type: standard (UI), programmatic (API), or terraform_provider"`
	// Status is the overall onboarding status (e.g., "Completely added", "Partially added", "Failed to add").
	Status string `json:"status,omitempty" mapstructure:"status" desc:"Overall onboarding status (e.g., Completely added, Partially added, Failed to add)"`
	// Services contains detailed information about each service deployed to this workspace including version, status, and errors.
	Services []IdsecCCEServiceDto `json:"services,omitempty" mapstructure:"services" desc:"Detailed service information including version, status, and errors"`
	// OrganizationID is the CCE onboarding ID of the parent organization (for AWS accounts that belong to an organization).
	OrganizationID string `json:"organization_id,omitempty" mapstructure:"organization_id" desc:"CCE onboarding ID of parent organization (for AWS accounts)"`
	// OrganizationName is the display name of the parent organization.
	OrganizationName string `json:"organization_name,omitempty" mapstructure:"organization_name" desc:"Display name of parent organization"`
}

// IdsecCCEPageOutput represents pagination information.
// OPENAPI-CORRELATION: PageOutput
type IdsecCCEPageOutput struct {
	PageNumber   int  `json:"page_number" mapstructure:"page_number" desc:"Current page number (1-indexed)"`
	PageSize     int  `json:"page_size" mapstructure:"page_size" desc:"Number of items per page"`
	IsLastPage   bool `json:"is_last_page" mapstructure:"is_last_page" desc:"Whether this is the last page of results"`
	TotalRecords int  `json:"total_records" mapstructure:"total_records" desc:"Total number of records across all pages"`
}
