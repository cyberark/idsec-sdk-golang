package actions

import certificatesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/certificates/models"

// ActionToSchemaMap is a map that defines the mapping between Access action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":  &certificatesmodels.IdsecSIACertificatesAddCertificate{},
	"delete":  &certificatesmodels.IdsecSIACertificatesDeleteCertificate{},
	"list":    nil,
	"list-by": &certificatesmodels.IdsecSIACertificatesFilter{},
	"update":  &certificatesmodels.IdsecSIACertificatesUpdateCertificate{},
	"get":     &certificatesmodels.IdsecSIACertificatesGetCertificate{},
	"stats":   nil,
}
