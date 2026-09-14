// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package usergroups

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/usergroups/actions"
)

// ServiceConfig is the configuration for the pcloud usergroups service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "pcloud-usergroups",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that generates a new instance of IdsecPCloudUserGroupsService.
var ServiceGenerator = NewIdsecPCloudUserGroupsService

// Module init registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
