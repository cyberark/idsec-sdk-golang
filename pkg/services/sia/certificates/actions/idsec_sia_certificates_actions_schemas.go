package actions

import certificatesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/certificates/models"

// ActionToSchemaMap is a map that defines the mapping between Access action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"add-certificate":      &certificatesmodels.IdsecSIACertificatesAddCertificate{},
	"delete-certificate":   &certificatesmodels.IdsecSIACertificatesDeleteCertificate{},
	"list-certificates":    nil,
	"list-certificates-by": &certificatesmodels.IdsecSIACertificatesFilter{},
	"update-certificate":   &certificatesmodels.IdsecSIACertificatesUpdateCertificate{},
	"certificate":          &certificatesmodels.IdsecSIACertificatesGetCertificate{},
	"certificates-stats":   nil,
}
