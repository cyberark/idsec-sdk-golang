// Package actions defines the CLI and Terraform action schemas for the IDSEC ARS requests service.
package actions

import requestsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/ars/requests/models"

// ActionToSchemaMap is a map that defines the mapping between ARS requests action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"submit":             &requestsmodels.IdsecARSSubmitAccessRequest{},
	"cancel":             &requestsmodels.IdsecARSCancelAccessRequest{},
	"finalize":           &requestsmodels.IdsecARSFinalizeAccessRequest{},
	"list":               nil,
	"list-by":            &requestsmodels.IdsecARSFilter{},
	"get":                &requestsmodels.IdsecARSGetAccessRequest{},
	"stats":              nil,
	"list-request-forms": &requestsmodels.IdsecARSListAccessRequestForms{},
}
