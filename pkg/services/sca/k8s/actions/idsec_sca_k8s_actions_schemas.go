package actions

import (
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

// ActionToSchemaMap defines the mapping of action names to their schema structs for the SCA k8s service.
var ActionToSchemaMap = map[string]interface{}{
	"list-targets": &k8smodels.IdsecSCAk8sListClustersRequest{},
	// elevate: generates a kubectl ExecCredential token via STS presign.
	// The Run function is overridden by IdsecKubectlLoginAction to produce raw
	// ExecCredential JSON to stdout instead of the standard args.PrintSuccess output.
	"elevate": &k8smodels.IdsecSCAK8sElevateKubectlRequest{},
	// generate-kubeconfig: fetches kubeconfig YAML from the API and writes it to disk.
	// The Run function is overridden by IdsecGenerateKubeconfigAction.
	"generate-kubeconfig": &k8smodels.IdsecSCAK8sGenerateKubeconfigRequest{},
}
