//go:build (e2e && sca) || e2e

package sca

import (
	"testing"

	policycloudaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess/models"
	scacloudaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudaccess/models"
)

type PrincipalFields struct {
	ID            string
	Name          string
	SourceDirName string
	SourceDirID   string
}

type K8sTestContext struct {
	AuthBlock      map[string]interface{}
	PrincipalBlock map[string]interface{}
	Targets        []map[string]interface{}
}

type K8sTargetConfig struct {
	PolicyTarget *scacloudaccessmodels.IdsecSCAEligibleTarget
	VerifyTarget *scacloudaccessmodels.IdsecSCAEligibleTarget
	Scope        string
	ClusterID    string
	FQDN         string
}

type K8sListTargetsConfig struct {
	ConfigBlockKey             string
	DisplayName                string
	CSP                        string
	PolicyNamePrefix           string
	PaginationPolicyNamePrefix string
	BuildTarget                func(map[string]interface{}) K8sTargetConfig
}

type kubeconfigFile struct {
	APIVersion     string           `yaml:"apiVersion"`
	Kind           string           `yaml:"kind"`
	Clusters       []any            `yaml:"clusters"`
	Contexts       []any            `yaml:"contexts"`
	CurrentContext string           `yaml:"current-context"`
	Users          []kubeconfigUser `yaml:"users"`
}

type kubeconfigUser struct {
	User struct {
		Exec struct {
			Command string   `yaml:"command"`
			Args    []string `yaml:"args"`
		} `yaml:"exec"`
	} `yaml:"user"`
}

type CloudAccessListTargetsConfig struct {
	ConfigBlockKey             string
	DisplayName                string
	CSP                        string
	PolicyNamePrefix           string
	PaginationPolicyNamePrefix string
	VerifyTarget               func(*testing.T, *policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy, *scacloudaccessmodels.IdsecSCAEligibleTarget, []scacloudaccessmodels.IdsecSCAEligibleTarget)
}

var AWSK8sListTargetsConfig = K8sListTargetsConfig{
	ConfigBlockKey:             "k8s_aws_clusters",
	DisplayName:                "K8s AWS Clusters ListTargets",
	CSP:                        "AWS",
	PolicyNamePrefix:           "sca_cli_k8s_aws_e2e",
	PaginationPolicyNamePrefix: "sca_cli_k8s_aws_pagination_e2e",
	BuildTarget:                buildAWSK8sTargetFromConfig,
}

var AzureK8sListTargetsConfig = K8sListTargetsConfig{
	ConfigBlockKey:             "k8s_azure_clusters",
	DisplayName:                "K8s Azure Clusters ListTargets",
	CSP:                        "AZURE",
	PolicyNamePrefix:           "sca_cli_k8s_azure_e2e",
	PaginationPolicyNamePrefix: "sca_cli_k8s_azure_pagination_e2e",
	BuildTarget:                buildAzureK8sTargetFromConfig,
}

var AWSCloudAccessListTargetsConfig = CloudAccessListTargetsConfig{
	ConfigBlockKey:             "aws_cloudaccess",
	DisplayName:                "CloudAccess AWS ListTargets",
	CSP:                        "AWS",
	PolicyNamePrefix:           "sca_cli_cloudaccess_aws_e2e",
	PaginationPolicyNamePrefix: "sca_cli_cloudaccess_aws_pagination_e2e",
	VerifyTarget: func(t *testing.T, _ *policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy, target *scacloudaccessmodels.IdsecSCAEligibleTarget, response []scacloudaccessmodels.IdsecSCAEligibleTarget) {
		verifyAWSCloudAccessTargetInListTargets(t, target, response)
	},
}

var AzureEntraIDCloudAccessListTargetsConfig = CloudAccessListTargetsConfig{
	ConfigBlockKey:             "azure_cloudaccess",
	DisplayName:                "CloudAccess Azure Entra ID ListTargets",
	CSP:                        "AZURE",
	PolicyNamePrefix:           "sca_cli_cloudaccess_azure_entra_id_e2e",
	PaginationPolicyNamePrefix: "sca_cli_cloudaccess_azure_entra_id_pagination_e2e",
	VerifyTarget: func(t *testing.T, fetchedPolicy *policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy, _ *scacloudaccessmodels.IdsecSCAEligibleTarget, response []scacloudaccessmodels.IdsecSCAEligibleTarget) {
		verifyCloudAccessTargetInListTargets(t, fetchedPolicy, response)
	},
}

var AzureResourceCloudAccessListTargetsConfig = CloudAccessListTargetsConfig{
	ConfigBlockKey:             "azure_cloudaccess_resource",
	DisplayName:                "CloudAccess Azure Resource ListTargets",
	CSP:                        "AZURE",
	PolicyNamePrefix:           "sca_cli_cloudaccess_azure_resource_e2e",
	PaginationPolicyNamePrefix: "sca_cli_cloudaccess_azure_resource_pagination_e2e",
	VerifyTarget: func(t *testing.T, fetchedPolicy *policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy, _ *scacloudaccessmodels.IdsecSCAEligibleTarget, response []scacloudaccessmodels.IdsecSCAEligibleTarget) {
		verifyCloudAccessTargetInListTargets(t, fetchedPolicy, response)
	},
}
