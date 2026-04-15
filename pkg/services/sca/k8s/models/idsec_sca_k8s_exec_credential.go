// Package models provides data structures for the SCA k8s service.
package models

// IdsecSCAK8sExecCredentialStatus holds the bearer token injected into kubectl.
//
// ExpirationTimestamp is intentionally absent: kubectl re-invokes the plugin
// reactively on a 401 Unauthorized from the cluster API server rather than
// proactively based on an expiry hint.
type IdsecSCAK8sExecCredentialStatus struct {
	Token string `json:"token"`
}

// IdsecSCAK8sExecCredential is the JSON object written to stdout for kubectl's
// exec credential plugin protocol.
//
// Reference: https://kubernetes.io/docs/reference/config-api/client-authentication.v1beta1/
type IdsecSCAK8sExecCredential struct {
	APIVersion string                          `json:"apiVersion"`
	Kind       string                          `json:"kind"`
	Status     IdsecSCAK8sExecCredentialStatus `json:"status"`
}
