//go:build (e2e && identity) || e2e

package identity

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	roles "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles"
	rolesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// TestIdentityRolesList exercises streaming List() against a live Identity tenant.
func TestIdentityRolesList(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: List Identity Roles")

		svc, err := ctx.API.IdentityRoles()
		require.NoError(t, err, "Failed to get Identity Roles service")

		t.Log("Listing identity roles...")
		pages, err := svc.List()
		require.NoError(t, err, "Failed to list roles")

		roleCount := 0
		for page := range pages {
			require.NotNil(t, page)
			for _, r := range page.Items {
				if r == nil {
					continue
				}
				if roleCount < 5 {
					t.Logf("  Role: %s (id=%s)", r.RoleName, r.RoleID)
				}
				roleCount++
			}
		}

		t.Logf("Total role items observed across pages: %d", roleCount)
	}, roles.ServiceConfig)
}

// TestIdentityRolesLifecycle creates a role, reads it back, updates description, verifies ListBy search, then deletes it.
func TestIdentityRolesLifecycle(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Identity Roles CRUD Lifecycle")

		svc, err := ctx.API.IdentityRoles()
		require.NoError(t, err, "Failed to get Identity Roles service")

		roleName := framework.RandomResourceName("e2e-role")
		initialDesc := "E2E temporary role — create"
		updatedDesc := "E2E temporary role — updated"

		t.Logf("Creating role: %s", roleName)
		created, err := svc.Create(&rolesmodels.IdsecIdentityCreateRole{
			RoleName:    roleName,
			Description: initialDesc,
		})
		require.NoError(t, err, "Create role failed")
		require.NotNil(t, created)
		require.NotEmpty(t, created.RoleID, "created role should have RoleID")
		assert.Equal(t, roleName, created.RoleName)

		deleted := false
		ctx.TrackResourceByType("IdentityRole", created.RoleID, func() error {
			if deleted {
				return nil
			}
			t.Logf("Cleaning up role: %s (%s)", created.RoleName, created.RoleID)
			return svc.Delete(&rolesmodels.IdsecIdentityDeleteRole{RoleID: created.RoleID})
		})

		t.Log("Get by name...")
		byName, err := svc.Get(&rolesmodels.IdsecIdentityGetRole{RoleName: roleName})
		require.NoError(t, err, "Get by role name failed")
		require.NotNil(t, byName)
		assert.Equal(t, created.RoleID, byName.RoleID)
		assert.Equal(t, roleName, byName.RoleName)
		if byName.Description != "" {
			assert.Equal(t, initialDesc, byName.Description)
		}

		t.Log("ListBy search...")
		filtered, err := svc.ListBy(&rolesmodels.IdsecIdentityRolesFilter{
			Search:       roleName,
			PageSize:     50,
			Limit:        100,
			MaxPageCount: 5,
		})
		require.NoError(t, err, "ListBy failed")
		found := false
		for page := range filtered {
			require.NotNil(t, page)
			for _, r := range page.Items {
				if r != nil && r.RoleID == created.RoleID {
					found = true
					break
				}
			}
		}
		assert.True(t, found, "ListBy should include the role created in this test")

		t.Log("Update description...")
		updated, err := svc.Update(&rolesmodels.IdsecIdentityUpdateRole{
			RoleID:      created.RoleID,
			Description: updatedDesc,
		})
		require.NoError(t, err, "Update role failed")
		require.NotNil(t, updated)
		if updated.Description != "" {
			assert.Equal(t, updatedDesc, updated.Description)
		}

		t.Log("Get by id...")
		byID, err := svc.Get(&rolesmodels.IdsecIdentityGetRole{RoleID: created.RoleID})
		require.NoError(t, err, "Get by role id failed")
		require.NotNil(t, byID)
		assert.Equal(t, created.RoleID, byID.RoleID)
		if byID.Description != "" {
			assert.Equal(t, updatedDesc, byID.Description)
		}

		t.Log("Delete role...")
		err = svc.Delete(&rolesmodels.IdsecIdentityDeleteRole{RoleID: created.RoleID})
		require.NoError(t, err, "Delete role failed")
		deleted = true

		t.Log("Lifecycle completed successfully")
	}, roles.ServiceConfig)
}

// TestIdentityRolesAttributesLifecycle exercises role attribute schema and per-role attribute values
// using uniquely named columns so the test does not collide with existing tenant schema.
func TestIdentityRolesAttributesLifecycle(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Identity Roles Attributes (schema + values)")

		svc, err := ctx.API.IdentityRoles()
		require.NoError(t, err, "Failed to get Identity Roles service")

		suffix := strings.ReplaceAll(framework.RandomResourceName("e2erattr"), "-", "")
		colDept := suffix + "_dept"
		colLoc := suffix + "_loc"
		colNames := []string{colDept, colLoc}

		roleName := framework.RandomResourceName("e2e-role-attr")
		t.Logf("Creating role: %s", roleName)
		created, err := svc.Create(&rolesmodels.IdsecIdentityCreateRole{
			RoleName:    roleName,
			Description: "E2E role for attribute schema tests",
		})
		require.NoError(t, err, "Create role failed")
		require.NotNil(t, created)
		require.NotEmpty(t, created.RoleID)

		schemaRemoved := false
		roleDeleted := false

		ctx.TrackResourceByType("IdentityRole", created.RoleID, func() error {
			if roleDeleted {
				return nil
			}
			t.Logf("Cleaning up role: %s (%s)", created.RoleName, created.RoleID)
			return svc.Delete(&rolesmodels.IdsecIdentityDeleteRole{RoleID: created.RoleID})
		})

		t.Logf("Creating attributes schema columns: %v", colNames)
		createdSchema, err := svc.CreateAttributesSchema(&rolesmodels.IdsecIdentityCreateRoleAttributesSchema{
			Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{
				{Name: colDept, Type: "Text"},
				{Name: colLoc, Type: "Text"},
			},
		})
		require.NoError(t, err, "CreateAttributesSchema failed")
		require.NotNil(t, createdSchema)
		require.GreaterOrEqual(t, len(createdSchema.Columns), 2)

		// Register after schema exists: cleanup runs LIFO (schema first, then role).
		// We do not call DeleteAttributes here: it clears values by posting empty strings,
		// which many Identity deployments reject ("Null or empty value for attribute can not insert").
		ctx.TrackResourceByType("RoleAttributesSchema", strings.Join(colNames, ","), func() error {
			if schemaRemoved {
				return nil
			}
			t.Logf("Cleaning up role attributes schema columns: %v", colNames)
			_, err := svc.DeleteAttributesSchema(&rolesmodels.IdsecIdentityDeleteRoleAttributesSchema{
				ColumnNames: colNames,
			})
			if err == nil {
				schemaRemoved = true
			}
			return err
		})

		t.Log("UpdateAttributesSchema (descriptions by name)...")
		updatedSchema, err := svc.UpdateAttributesSchema(&rolesmodels.IdsecIdentityUpdateRoleAttributesSchema{
			Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{
				{Name: colDept, Description: "E2E department column"},
				{Name: colLoc, Description: "E2E location column"},
			},
		})
		require.NoError(t, err, "UpdateAttributesSchema failed")
		require.NotNil(t, updatedSchema)

		t.Log("AttributesSchema (GET)...")
		fullSchema, err := svc.AttributesSchema()
		require.NoError(t, err, "AttributesSchema failed")
		require.NotNil(t, fullSchema)
		foundDept := false
		foundLoc := false
		for _, c := range fullSchema.Columns {
			if c.Name == colDept {
				foundDept = true
			}
			if c.Name == colLoc {
				foundLoc = true
			}
		}
		assert.True(t, foundDept && foundLoc, "schema GET should include columns created in this test")

		deptVal := "Engineering"
		locVal := "Tel Aviv"
		t.Log("UpsertAttributes...")
		upserted, err := svc.UpsertAttributes(&rolesmodels.IdsecIdentityUpsertRoleAttributes{
			RoleID: created.RoleID,
			Attributes: map[string]string{
				colDept: deptVal,
				colLoc:  locVal,
			},
		})
		require.NoError(t, err, "UpsertAttributes failed")
		require.NotNil(t, upserted)
		assert.Equal(t, deptVal, upserted.Attributes[colDept])
		assert.Equal(t, locVal, upserted.Attributes[colLoc])

		t.Log("GetAttributes...")
		current, err := svc.GetAttributes(&rolesmodels.IdsecIdentityGetRoleAttributes{RoleID: created.RoleID})
		require.NoError(t, err, "GetAttributes failed")
		require.NotNil(t, current)
		assert.Equal(t, deptVal, current.Attributes[colDept])
		assert.Equal(t, locVal, current.Attributes[colLoc])

		t.Log("Get role (merged attributes)...")
		withAttrs, err := svc.Get(&rolesmodels.IdsecIdentityGetRole{RoleID: created.RoleID})
		require.NoError(t, err, "Get role failed")
		require.NotNil(t, withAttrs)
		if withAttrs.RoleAttributes != nil {
			assert.Equal(t, deptVal, withAttrs.RoleAttributes[colDept])
			assert.Equal(t, locVal, withAttrs.RoleAttributes[colLoc])
		}

		t.Log("Tear down schema columns then role (skip DeleteAttributes — empty values rejected by API)...")
		_, err = svc.DeleteAttributesSchema(&rolesmodels.IdsecIdentityDeleteRoleAttributesSchema{
			ColumnNames: colNames,
		})
		require.NoError(t, err, "DeleteAttributesSchema failed")
		schemaRemoved = true

		err = svc.Delete(&rolesmodels.IdsecIdentityDeleteRole{RoleID: created.RoleID})
		require.NoError(t, err, "Delete role failed")
		roleDeleted = true

		t.Log("Roles attributes lifecycle completed successfully")
	}, roles.ServiceConfig)
}
