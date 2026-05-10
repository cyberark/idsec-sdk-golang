package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity"
	rolesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles/models"
)

func main() {
	// Perform authentication using IdsecISPAuth to the platform
	// First, create an ISP authentication class
	// Afterwards, perform the authentication
	ispAuth := auth.NewIdsecISPAuth(false)
	_, err := ispAuth.Authenticate(
		nil,
		&authmodels.IdsecAuthProfile{
			Username:           "user@cyberark.cloud.12345",
			AuthMethod:         authmodels.Identity,
			AuthMethodSettings: &authmodels.IdentityIdsecAuthMethodSettings{},
		},
		&authmodels.IdsecSecret{
			Secret: os.Getenv("IDSEC_SECRET"),
		},
		false,
		false,
	)
	if err != nil {
		panic(err)
	}

	identityAPI, err := identity.NewIdsecIdentityAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	role, err := identityAPI.Roles().Create(&rolesmodels.IdsecIdentityCreateRole{RoleName: "myRol1322323e"})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Role: %v\n", role)

	createdSchema, err := identityAPI.Roles().CreateAttributesSchema(&rolesmodels.IdsecIdentityCreateRoleAttributesSchema{
		Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{
			{Name: "department", Type: "Text"},
			{Name: "location", Type: "Text"},
		},
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Role Attributes Schema (created): %v\n", createdSchema)

	updatedSchema, err := identityAPI.Roles().UpdateAttributesSchema(&rolesmodels.IdsecIdentityUpdateRoleAttributesSchema{
		Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{
			{Name: "department", Description: "Department attribute"},
			{Name: "location", Description: "Location attribute"},
		},
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Role Attributes Schema (after description update): %v\n", updatedSchema)
	updateByIdSchema, err := identityAPI.Roles().UpdateAttributesSchema(&rolesmodels.IdsecIdentityUpdateRoleAttributesSchema{
		Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{
			{ID: createdSchema.Columns[0].ID, Description: "Department attribut23"},
			{ID: createdSchema.Columns[1].ID, Description: "Location attribute23"},
		},
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Role Attributes Schema (after description update by ID): %v\n", updateByIdSchema)

	schema, err := identityAPI.Roles().AttributesSchema()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Role Attributes Schema GET: %v\n", schema)

	upsertedAttributes, err := identityAPI.Roles().UpsertAttributes(&rolesmodels.IdsecIdentityUpsertRoleAttributes{
		RoleID: role.RoleID,
		Attributes: map[string]string{
			"department": "Engineering",
			"location":   "Tel Aviv",
		},
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Role Attributes (upserted): %v\n", upsertedAttributes)

	currentAttributes, err := identityAPI.Roles().GetAttributes(&rolesmodels.IdsecIdentityGetRoleAttributes{
		RoleID: role.RoleID,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Role Attributes (current): %v\n", currentAttributes)
	roleWithAttributes, err := identityAPI.Roles().Get(&rolesmodels.IdsecIdentityGetRole{
		RoleID: role.RoleID,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Role (after upsert attrs): %v\n", roleWithAttributes)

	clearedAttributes, err := identityAPI.Roles().DeleteAttributes(&rolesmodels.IdsecIdentityDeleteRoleAttributes{
		RoleID:         role.RoleID,
		AttributeNames: []string{"department"},
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Role Attributes (after clearing department): %v\n", clearedAttributes)

	newSchema, err := identityAPI.Roles().DeleteAttributesSchema(&rolesmodels.IdsecIdentityDeleteRoleAttributesSchema{
		ColumnNames: []string{"department", "location"},
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Role Attributes Schema NEW: %v\n", newSchema)
}
