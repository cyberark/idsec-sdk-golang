// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/usergroups/models"
)

// ActionToSchemaMap maps action names to their request schema structs.
//
// The group lifecycle uses the create/get/update/delete names shared by the other pCloud
// services, while the membership actions keep their own add-member/delete-member names.
var ActionToSchemaMap = map[string]interface{}{
	"create":        &models.IdsecPCloudAddUserGroup{},
	"get":           &models.IdsecPCloudGetUserGroup{},
	"update":        &models.IdsecPCloudUpdateUserGroup{},
	"delete":        &models.IdsecPCloudDeleteUserGroup{},
	"list":          nil,
	"list-by":       &models.IdsecPCloudUserGroupsFilters{},
	"add-member":    &models.IdsecPCloudAddUserGroupMember{},
	"delete-member": &models.IdsecPCloudDeleteUserGroupMember{},
}
