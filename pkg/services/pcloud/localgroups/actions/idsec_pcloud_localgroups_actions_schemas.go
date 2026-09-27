// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package actions

import localmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/localgroups/models"

// ActionToSchemaMap maps action names to their request schema structs.
//
// The group lifecycle uses the create/get/update/delete names shared by the other pCloud
// services, while the membership actions keep their own add-member/delete-member names.
var ActionToSchemaMap = map[string]interface{}{
	"create":        &localmodels.IdsecPCloudAddLocalGroup{},
	"get":           &localmodels.IdsecPCloudGetLocalGroup{},
	"update":        &localmodels.IdsecPCloudUpdateLocalGroup{},
	"delete":        &localmodels.IdsecPCloudDeleteLocalGroup{},
	"list":          nil,
	"list-by":       &localmodels.IdsecPCloudLocalGroupsFilters{},
	"add-member":    &localmodels.IdsecPCloudAddLocalGroupMember{},
	"get-member":    &localmodels.IdsecPCloudGetLocalGroupMember{},
	"delete-member": &localmodels.IdsecPCloudDeleteLocalGroupMember{},
}
