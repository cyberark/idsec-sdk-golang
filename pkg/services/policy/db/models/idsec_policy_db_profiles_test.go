package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// Verify that unset role collections serialize to empty (non-nil) values, so
// they marshal to {} / [] rather than null (which the backend rejects), and
// that set fields pass through unchanged.
func TestSqlServerAuthProfileSerialize_UnsetCollectionsAreEmptyNotNil(t *testing.T) {
	t.Run("only_global_custom_roles_set", func(t *testing.T) {
		profile := &IdsecPolicyDBSqlServerAuthProfile{
			GlobalCustomRoles: []string{"##MS_DatabaseConnector##"},
		}
		out, err := json.Marshal(profile.Serialize())
		require.NoError(t, err)
		require.JSONEq(t, `{
			"globalBuiltinRoles": [],
			"globalCustomRoles": ["##MS_DatabaseConnector##"],
			"databaseBuiltinRoles": {},
			"databaseCustomRoles": {}
		}`, string(out))
	})

	t.Run("all_fields_unset", func(t *testing.T) {
		out, err := json.Marshal((&IdsecPolicyDBSqlServerAuthProfile{}).Serialize())
		require.NoError(t, err)
		require.JSONEq(t, `{
			"globalBuiltinRoles": [],
			"globalCustomRoles": [],
			"databaseBuiltinRoles": {},
			"databaseCustomRoles": {}
		}`, string(out))
	})
}

// Verify that populated role collections pass through unchanged.
func TestSqlServerAuthProfileSerialize_PopulatedCollectionsPreserved(t *testing.T) {
	profile := &IdsecPolicyDBSqlServerAuthProfile{
		GlobalBuiltinRoles:   []string{"sysadmin"},
		GlobalCustomRoles:    []string{"##MS_DatabaseConnector##"},
		DatabaseBuiltinRoles: map[string][]string{"salesdb": {"db_datareader"}},
		DatabaseCustomRoles:  map[string][]string{"salesdb": {"custom_role"}},
	}
	out, err := json.Marshal(profile.Serialize())
	require.NoError(t, err)
	require.JSONEq(t, `{
		"globalBuiltinRoles": ["sysadmin"],
		"globalCustomRoles": ["##MS_DatabaseConnector##"],
		"databaseBuiltinRoles": {"salesdb": ["db_datareader"]},
		"databaseCustomRoles": {"salesdb": ["custom_role"]}
	}`, string(out))
}

// Verify that unset role collections serialize to empty (non-nil) values, so
// they marshal to {} / [] rather than null (which the backend rejects), and
// that set fields pass through unchanged.
func TestMongoAuthProfileSerialize_UnsetCollectionsAreEmptyNotNil(t *testing.T) {
	t.Run("only_global_builtin_roles_set", func(t *testing.T) {
		profile := &IdsecPolicyDBMongoAuthProfile{
			GlobalBuiltinRoles: []string{"readAnyDatabase"},
		}
		out, err := json.Marshal(profile.Serialize())
		require.NoError(t, err)
		require.JSONEq(t, `{
			"globalBuiltinRoles": ["readAnyDatabase"],
			"databaseBuiltinRoles": {},
			"databaseCustomRoles": {}
		}`, string(out))
	})

	t.Run("all_fields_unset", func(t *testing.T) {
		out, err := json.Marshal((&IdsecPolicyDBMongoAuthProfile{}).Serialize())
		require.NoError(t, err)
		require.JSONEq(t, `{
			"globalBuiltinRoles": [],
			"databaseBuiltinRoles": {},
			"databaseCustomRoles": {}
		}`, string(out))
	})
}

// Verify that populated role collections pass through unchanged.
func TestMongoAuthProfileSerialize_PopulatedCollectionsPreserved(t *testing.T) {
	profile := &IdsecPolicyDBMongoAuthProfile{
		GlobalBuiltinRoles:   []string{"readAnyDatabase"},
		DatabaseBuiltinRoles: map[string][]string{"admin": {"read"}},
		DatabaseCustomRoles:  map[string][]string{"admin": {"customRead"}},
	}
	out, err := json.Marshal(profile.Serialize())
	require.NoError(t, err)
	require.JSONEq(t, `{
		"globalBuiltinRoles": ["readAnyDatabase"],
		"databaseBuiltinRoles": {"admin": ["read"]},
		"databaseCustomRoles": {"admin": ["customRead"]}
	}`, string(out))
}
