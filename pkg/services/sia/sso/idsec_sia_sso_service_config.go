package sso

import (
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso/actions"
)

// ServiceConfig is the configuration for the SSO service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-sso",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// serviceGeneratorWrapper wraps the NewIdsecSIASSOService to match the expected ServiceGenerator signature.
// It creates an IdsecISPBaseService from the provided authenticators before calling the actual constructor.
func serviceGeneratorWrapper(authenticators ...auth.IdsecAuth) (*IdsecSIASSOService, error) {
	if len(authenticators) == 0 {
		return nil, fmt.Errorf("at least one authenticator required")
	}

	var ispAuth *auth.IdsecISPAuth
	for _, authenticator := range authenticators {
		if auth, ok := authenticator.(*auth.IdsecISPAuth); ok {
			ispAuth = auth
			break
		}
	}

	if ispAuth == nil {
		return nil, fmt.Errorf("ISP authenticator required")
	}

	// Create ISP base service
	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "dpa", ".", "", func(client *common.IdsecClient) error {
		return isp.RefreshClient(client, ispAuth)
	})
	if err != nil {
		return nil, err
	}

	return NewIdsecSIASSOService(ispBaseService)
}

// ServiceGenerator is the function that creates a new instance of the SIA SSO service.
var ServiceGenerator = serviceGeneratorWrapper

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
