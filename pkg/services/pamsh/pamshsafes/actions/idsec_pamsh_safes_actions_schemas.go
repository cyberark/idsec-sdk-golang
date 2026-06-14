package actions

import safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshsafes/models"

// ActionToSchemaMap maps action names to schema types for pamsh safes (PAS REST wire shape).
var ActionToSchemaMap = map[string]interface{}{
	"create":        &safesmodels.IdsecPamshAddSafe{},
	"update":        &safesmodels.IdsecPamshUpdateSafe{},
	"delete":        &safesmodels.IdsecPamshDeleteSafe{},
	"get":           &safesmodels.IdsecPamshGetSafe{},
	"add-member":    &safesmodels.IdsecPamshAddSafeMember{},
	"update-member": &safesmodels.IdsecPamshUpdateSafeMember{},
	"delete-member": &safesmodels.IdsecPamshDeleteSafeMember{},
	"get-member":    &safesmodels.IdsecPamshGetSafeMember{},
}
