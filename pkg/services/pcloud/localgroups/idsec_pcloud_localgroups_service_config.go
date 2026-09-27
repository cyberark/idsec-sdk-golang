// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package localgroups

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/localgroups/actions"
)

// ServiceConfig is the configuration for the pcloud localgroups service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "pcloud-localgroups",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that generates a new instance of IdsecPCloudLocalGroupsService.
var ServiceGenerator = NewIdsecPCloudLocalGroupsService

// Module init registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
