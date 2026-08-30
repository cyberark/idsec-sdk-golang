package actions

import doctormodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/doctor/models"

// ActionToSchemaMap maps doctor action names to their request schema types.
var ActionToSchemaMap = map[string]interface{}{
	"check":                   &doctormodels.IdsecSIADoctorCheck{},
	"check-client":            &doctormodels.IdsecSIADoctorCheckClient{},
	"check-target":            &doctormodels.IdsecSIADoctorCheckTarget{},
	"check-connector":         &doctormodels.IdsecSIADoctorCheckConnector{},
	"check-domain-controller": &doctormodels.IdsecSIADoctorCheckDomainController{},
}
