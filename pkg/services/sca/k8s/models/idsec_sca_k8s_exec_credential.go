// Package models provides data structures for the SCA k8s service.
package models

// IdsecSCAK8sExecCredentialStatus holds the authentication credentials injected
// into kubectl. For direct connections a bearer token is provided; for proxy
// connections a client certificate and key are provided instead.
//
// ExpirationTimestamp, when set (RFC3339), lets client-go cache the credential
// in-process and skip re-invoking the plugin until that time. Azure direct
// emits it (derived from the AKS JWT exp); AWS and proxy paths leave it empty
// and rely on reactive 401-driven refresh.
//
// Reference: https://kubernetes.io/docs/reference/config-api/client-authentication.v1beta1/
type IdsecSCAK8sExecCredentialStatus struct {
	Token                 string `json:"token,omitempty"`
	ExpirationTimestamp   string `json:"expirationTimestamp,omitempty"`
	ClientCertificateData string `json:"clientCertificateData,omitempty"`
	ClientKeyData         string `json:"clientKeyData,omitempty"`
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
