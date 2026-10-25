// Package securezones provides the SDK service for managing Identity Cloud secure zones
// (also referred to as on-premises detection ranges). It wraps the Core/UpdatePremDetectRange,
// Core/DeletePremDetectRange, Core/GetPremDetectRanges, Core/EnablePremDetectRange, and
// Core/DisablePremDetectRange endpoints on the CyberArk Identity Service Provider.
package securezones

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/securezones/actions"
)

// ServiceConfig is the configuration for the identity-securezones service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "identity-securezones",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that generates a new instance of the IdsecIdentitySecureZonesService.
var ServiceGenerator = NewIdsecIdentitySecureZonesService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
