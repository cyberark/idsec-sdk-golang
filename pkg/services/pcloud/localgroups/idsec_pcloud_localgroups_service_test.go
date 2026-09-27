// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package localgroups_test

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	pcloudint "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/internal"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/localgroups"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/localgroups/actions"
	localmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/localgroups/models"
)

func parseJSONBody(r *http.Request, out interface{}) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

const (
	localGroupsPath = "/PasswordVault/API/UserGroups"
	localGroupPath  = "/PasswordVault/API/UserGroups/g-7"
	groupPath5      = "/PasswordVault/API/UserGroups/g-5"
	membersPath5    = "/PasswordVault/API/UserGroups/g-5/Members"
)

func newTestLocalGroupsService(t *testing.T, handler http.HandlerFunc) *localgroups.IdsecPCloudLocalGroupsService {
	t.Helper()
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, handler)
	t.Cleanup(cleanup)
	return &localgroups.IdsecPCloudLocalGroupsService{
		IdsecBaseService:    parts.BaseService,
		IdsecISPBaseService: parts.ISPBase,
	}
}

// TestLocalGroupsServiceIsCallableByActionName verifies that the service is registered and that
// every action name in ActionToSchemaMap maps to a method with the correct signature. This catches
// the class of bug where the schema and the method name disagree — a bug that only surfaces at
// apply time without this test.
func TestLocalGroupsServiceIsCallableByActionName(t *testing.T) {
	t.Parallel()
	config, err := services.GetServiceConfig("pcloud-localgroups")
	require.NoError(t, err, "the package's init() must register the service")
	require.NotNil(t, localgroups.ServiceGenerator, "ServiceGenerator must be set")
	require.Equal(t, actions.ActionToSchemaMap, config.ActionSchemas)

	actionMethods := map[string]string{
		"create":        "Create",
		"get":           "Get",
		"update":        "Update",
		"delete":        "Delete",
		"list":          "List",
		"list-by":       "ListBy",
		"add-member":    "AddMember",
		"get-member":    "GetMember",
		"delete-member": "DeleteMember",
	}
	require.Len(t, actionMethods, len(config.ActionSchemas), "every registered action must be accounted for here")

	svcVal := reflect.ValueOf((*localgroups.IdsecPCloudLocalGroupsService)(nil))
	for action, methodName := range actionMethods {
		schema, registered := config.ActionSchemas[action]
		require.True(t, registered, "action %q is not registered", action)

		method := svcVal.MethodByName(methodName)
		require.True(t, method.IsValid(), "action %q names method %s which the service does not have", action, methodName)
		if schema == nil {
			require.Zero(t, method.Type().NumIn(), "action %q registers no schema, so %s must take no argument", action, methodName)
			continue
		}
		require.Equal(t, 1, method.Type().NumIn(), "%s must take exactly the action's schema", methodName)
		require.Equal(t, reflect.TypeOf(schema), method.Type().In(0),
			"%s must take the type registered for action %q", methodName, action)
	}
}

func TestLocalGroupsCreate_normalizesIDIntoGroupID(t *testing.T) {
	t.Parallel()
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != localGroupsPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"g-7","groupName":"TestGroup","description":"desc","location":"\\","groupType":"Vault"}`))
	})

	group, err := svc.Create(&localmodels.IdsecPCloudAddLocalGroup{GroupName: "TestGroup"})
	require.NoError(t, err)
	require.Equal(t, "g-7", group.GroupID, "the API returns \"id\"; it must be normalized to group_id")
	require.Equal(t, "TestGroup", group.GroupName)
	require.Equal(t, "Vault", group.GroupType)
}

func TestLocalGroupsCreate_unexpectedStatus_returnsError(t *testing.T) {
	t.Parallel()
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ErrorCode":"CAWS00001E"}`))
	})

	group, err := svc.Create(&localmodels.IdsecPCloudAddLocalGroup{GroupName: "TestGroup"})
	require.Error(t, err)
	require.Nil(t, group)
	require.Contains(t, err.Error(), "failed to create local group")
}

func TestLocalGroupsGet_byNameOnly_resolvesThroughList(t *testing.T) {
	t.Parallel()
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != localGroupsPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[{"id":"g-1","groupName":"Other"},{"id":"g-7","groupName":"TestGroup","groupType":"Vault"}]}`))
	})

	group, err := svc.Get(&localmodels.IdsecPCloudGetLocalGroup{GroupName: "testgroup"})
	require.NoError(t, err)
	require.Equal(t, "g-7", group.GroupID)
	require.Equal(t, "TestGroup", group.GroupName)
}

func TestLocalGroupsGet_byIDAndName_matchesBoth(t *testing.T) {
	t.Parallel()
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != localGroupsPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[{"id":"g-1","groupName":"Other"},{"id":"g-7","groupName":"TestGroup"}]}`))
	})

	group, err := svc.Get(&localmodels.IdsecPCloudGetLocalGroup{GroupID: "g-7", GroupName: "testgroup"})
	require.NoError(t, err)
	require.Equal(t, "g-7", group.GroupID)
	require.Equal(t, "TestGroup", group.GroupName)
}

func TestLocalGroupsDelete_acceptsOKAndNoContent(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusOK, http.StatusNoContent} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete || r.URL.Path != localGroupPath {
					http.NotFound(w, r)
					return
				}
				w.WriteHeader(status)
			})
			err := svc.Delete(&localmodels.IdsecPCloudDeleteLocalGroup{GroupID: "g-7"})
			require.NoError(t, err)
		})
	}
}

func TestLocalGroupsAddMember_success(t *testing.T) {
	t.Parallel()
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != membersPath5 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"m-11","memberName":"JDoe","memberType":"User"}`))
	})

	member, err := svc.AddMember(&localmodels.IdsecPCloudAddLocalGroupMember{
		GroupID:    "g-5",
		MemberName: "JDoe",
		MemberType: "User",
	})
	require.NoError(t, err)
	require.Equal(t, "g-5", member.GroupID)
	require.Equal(t, "JDoe", member.MemberName)
}

// TestLocalGroupsGetMember_pvwaPayload uses the real PVWA response: members are embedded in the
// group's own representation under the "members" key, with "username" and "id" fields.
// PVWA has no GET on the /Members sub-resource — the group's own GET is the only source.
func TestLocalGroupsGetMember_pvwaPayload(t *testing.T) {
	t.Parallel()
	const groupBody = `{"id":"g-5","groupName":"G","groupType":"Vault","location":"\\","members":[{"username":"Admin","id":2},{"username":"JDoe","id":11}]}`

	var groupGETs, membersGETs int
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == groupPath5:
			groupGETs++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(groupBody))
		case r.Method == http.MethodGet && r.URL.Path == membersPath5:
			membersGETs++
			w.Header().Set("Allow", "POST, DELETE")
			w.WriteHeader(http.StatusMethodNotAllowed)
		default:
			http.NotFound(w, r)
		}
	})

	member, err := svc.GetMember(&localmodels.IdsecPCloudGetLocalGroupMember{
		GroupID:    "g-5",
		MemberName: "jdoe",
	})
	require.Equal(t, 1, groupGETs, "the group's own route is the one that reports members")
	require.Zero(t, membersGETs, "the /Members sub-resource has no GET — asking it wastes a round trip")
	require.NoError(t, err)
	require.Equal(t, "JDoe", member.MemberName, "Vault's own spelling must be returned, not the caller's")
	require.Equal(t, "g-5", member.GroupID)
}

func TestLocalGroupsGetMember_notAMember_wrapsNotFoundSentinel(t *testing.T) {
	t.Parallel()
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != groupPath5 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"g-5","groupName":"G","members":[{"username":"Admin","id":2}]}`))
	})

	member, err := svc.GetMember(&localmodels.IdsecPCloudGetLocalGroupMember{GroupID: "g-5", MemberName: "jdoe"})
	require.Nil(t, member)
	require.ErrorIs(t, err, localgroups.ErrLocalGroupMemberNotFound)
	require.ErrorIs(t, err, common.ErrNotFound, "provider Read handlers depend on the common.ErrNotFound chain")
	require.Contains(t, err.Error(), "jdoe")
}

// A group with no members omits the "members" key entirely rather than sending an empty array.
func TestLocalGroupsGetMember_emptyGroup_wrapsNotFoundSentinel(t *testing.T) {
	t.Parallel()
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != groupPath5 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"g-5","groupName":"G"}`))
	})

	member, err := svc.GetMember(&localmodels.IdsecPCloudGetLocalGroupMember{GroupID: "g-5", MemberName: "jdoe"})
	require.Nil(t, member)
	require.ErrorIs(t, err, localgroups.ErrLocalGroupMemberNotFound,
		"an omitted members key means the group is empty, not that the response was unreadable")
	require.ErrorIs(t, err, common.ErrNotFound, "provider Read handlers depend on the common.ErrNotFound chain")
}

func TestLocalGroupsGetMember_groupGone_wrapsNotFoundSentinel(t *testing.T) {
	t.Parallel()
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != groupPath5 {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"ErrorCode":"PASWS199E","ErrorMessage":"Group not found."}`))
	})

	member, err := svc.GetMember(&localmodels.IdsecPCloudGetLocalGroupMember{GroupID: "g-5", MemberName: "jdoe"})
	require.Nil(t, member)
	require.ErrorIs(t, err, localgroups.ErrLocalGroupMemberNotFound, "a gone group means the membership is also gone")
	require.ErrorIs(t, err, common.ErrNotFound, "provider Read handlers depend on the common.ErrNotFound chain")
}

func TestLocalGroupsGetMember_groupUnreadable_returnsReadError(t *testing.T) {
	t.Parallel()
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	})

	member, err := svc.GetMember(&localmodels.IdsecPCloudGetLocalGroupMember{GroupID: "g-5", MemberName: "jdoe"})
	require.Nil(t, member)
	require.Error(t, err)
	require.NotErrorIs(t, err, localgroups.ErrLocalGroupMemberNotFound,
		"a read failure says nothing about whether the member is still there")
	require.Contains(t, err.Error(), "failed to read members of local group g-5")
}

func TestLocalGroupsGetMember_notFoundGatedOnPVWACode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		status   int
		body     string
		sentinel bool
	}{
		{
			name:     "PVWA group-not-found",
			status:   http.StatusNotFound,
			body:     `{"ErrorCode":"PASWS199E","ErrorMessage":"Group ID [g-5] was not found."}`,
			sentinel: true,
		},
		{
			name:   "404 from non-PVWA (HTML)",
			status: http.StatusNotFound,
			body:   `<html><title>404</title></html>`,
		},
		{
			name:   "404 with other PVWA code",
			status: http.StatusNotFound,
			body:   `{"ErrorCode":"PASWS011E","ErrorMessage":"Something else."}`,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != groupPath5 {
					http.NotFound(w, r)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})

			member, err := svc.GetMember(&localmodels.IdsecPCloudGetLocalGroupMember{GroupID: "g-5", MemberName: "jdoe"})
			require.Nil(t, member)
			require.Error(t, err)
			if tc.sentinel {
				require.ErrorIs(t, err, localgroups.ErrLocalGroupMemberNotFound)
				require.ErrorIs(t, err, common.ErrNotFound, "provider Read handlers depend on the common.ErrNotFound chain")
			} else {
				require.NotErrorIs(t, err, localgroups.ErrLocalGroupMemberNotFound,
					"a 404 without the PVWA group-not-found code must not be treated as absent membership")
			}
		})
	}
}

func TestLocalGroupsDeleteMember_putsMemberNameInPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		memberName string
		wantPath   string
	}{
		{"plain", "JDoe", "/PasswordVault/API/UserGroups/g-5/Members/JDoe"},
		{"with space", "John Doe", "/PasswordVault/API/UserGroups/g-5/Members/John Doe"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var gotPath string
			svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.WriteHeader(http.StatusNoContent)
			})

			err := svc.DeleteMember(&localmodels.IdsecPCloudDeleteLocalGroupMember{
				GroupID:    "g-5",
				MemberName: tc.memberName,
			})
			require.NoError(t, err)
			require.Equal(t, tc.wantPath, gotPath)
		})
	}
}

func TestLocalGroupsUpdate_success(t *testing.T) {
	t.Parallel()
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == localGroupPath:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"g-7","groupName":"Renamed","description":"d","location":"\\","groupType":"Vault"}`))
		default:
			http.NotFound(w, r)
		}
	})

	group, err := svc.Update(&localmodels.IdsecPCloudUpdateLocalGroup{GroupID: "g-7", GroupName: "Renamed"})
	require.NoError(t, err)
	require.Equal(t, "g-7", group.GroupID)
	require.Equal(t, "Renamed", group.GroupName)
}

// TestLocalGroupsUpdate_autoFetchesGroupName verifies that Update calls Get first when the caller
// omits GroupName, because PVWA's BaseUserGroup has [CybRequired] on groupName and would reject
// the PUT without it.
func TestLocalGroupsUpdate_autoFetchesGroupName(t *testing.T) {
	t.Parallel()
	var getCalled bool
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == localGroupsPath:
			// Get resolves GroupID by listing all groups (no Search filter when only ID is set).
			getCalled = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"value":[{"id":"g-7","groupName":"ExistingName","groupType":"Vault"}]}`))
		case r.Method == http.MethodPut && r.URL.Path == localGroupPath:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"g-7","groupName":"ExistingName","groupType":"Vault"}`))
		default:
			http.NotFound(w, r)
		}
	})

	group, err := svc.Update(&localmodels.IdsecPCloudUpdateLocalGroup{GroupID: "g-7"})
	require.NoError(t, err)
	require.True(t, getCalled, "Update must fetch the existing name when GroupName is not supplied")
	require.Equal(t, "ExistingName", group.GroupName)
}

func TestLocalGroupsListBy_passesFiltersAsQueryParams(t *testing.T) {
	t.Parallel()
	var gotSearch, gotSort string
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != localGroupsPath {
			http.NotFound(w, r)
			return
		}
		gotSearch = r.URL.Query().Get("search")
		gotSort = r.URL.Query().Get("sort")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[]}`))
	})

	pages, err := svc.ListBy(&localmodels.IdsecPCloudLocalGroupsFilters{Search: "mygroup", Sort: "groupName"})
	require.NoError(t, err)
	for range pages {
	}
	require.Equal(t, "mygroup", gotSearch)
	require.Equal(t, "groupName", gotSort)
}

// TestLocalGroupsAddMember_pvwaReturnsNumericID verifies that a numeric "id" in the AddMember
// response is normalised to a string MembershipID, matching how PVWA sends member IDs.
func TestLocalGroupsAddMember_pvwaReturnsNumericID(t *testing.T) {
	t.Parallel()
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != membersPath5 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":42,"memberId":"JDoe","memberType":"Vault"}`))
	})

	member, err := svc.AddMember(&localmodels.IdsecPCloudAddLocalGroupMember{
		GroupID:    "g-5",
		MemberName: "JDoe",
		MemberType: "User",
	})
	require.NoError(t, err)
	require.Equal(t, "42", member.MembershipID, "numeric id must be stringified")
	require.Equal(t, "JDoe", member.MemberName)
}

func TestLocalGroupsGetMember_withoutGroupIDOrMemberName_returnsError(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		input *localmodels.IdsecPCloudGetLocalGroupMember
	}{
		{"no group ID", &localmodels.IdsecPCloudGetLocalGroupMember{MemberName: "jdoe"}},
		{"no member name", &localmodels.IdsecPCloudGetLocalGroupMember{GroupID: "g-5"}},
		{"neither", &localmodels.IdsecPCloudGetLocalGroupMember{}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var requests int
			svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.WriteHeader(http.StatusOK)
			})

			member, err := svc.GetMember(tc.input)
			require.Error(t, err)
			require.Nil(t, member)
			require.Zero(t, requests, "no HTTP request should be made for invalid input")
		})
	}
}

// TestLocalGroupsGet_sendsIncludePredefinedUsers verifies that Get always sends the
// includePredefinedUsers=true query parameter so built-in Vault groups are visible.
func TestLocalGroupsGet_sendsIncludePredefinedUsers(t *testing.T) {
	t.Parallel()
	var gotIncludePredefined string
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != localGroupsPath {
			http.NotFound(w, r)
			return
		}
		gotIncludePredefined = r.URL.Query().Get("includePredefinedUsers")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[{"id":"g-7","groupName":"Vault Admins","groupType":"Vault"}]}`))
	})

	_, err := svc.Get(&localmodels.IdsecPCloudGetLocalGroup{GroupName: "Vault Admins"})
	require.NoError(t, err)
	require.Equal(t, "true", gotIncludePredefined, "Get must always send includePredefinedUsers=true")
}

// TestLocalGroupsListBy_sendsIncludePredefinedUsers verifies that the filter field is forwarded
// as the includePredefinedUsers query parameter when true.
func TestLocalGroupsListBy_sendsIncludePredefinedUsers(t *testing.T) {
	t.Parallel()
	var gotParam string
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != localGroupsPath {
			http.NotFound(w, r)
			return
		}
		gotParam = r.URL.Query().Get("includePredefinedUsers")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[]}`))
	})

	pages, err := svc.ListBy(&localmodels.IdsecPCloudLocalGroupsFilters{IncludePredefinedUsers: true})
	require.NoError(t, err)
	for range pages {
	}
	require.Equal(t, "true", gotParam, "includePredefinedUsers filter must be forwarded as a query param")
}

// TestLocalGroupsListBy_omitsIncludePredefinedUsers verifies that the param is not sent when false.
func TestLocalGroupsListBy_omitsIncludePredefinedUsers(t *testing.T) {
	t.Parallel()
	var gotQuery string
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[]}`))
	})

	pages, err := svc.ListBy(&localmodels.IdsecPCloudLocalGroupsFilters{})
	require.NoError(t, err)
	for range pages {
	}
	require.NotContains(t, gotQuery, "includePredefinedUsers", "param must not be sent when false")
}

// TestLocalGroupsEmptyGroupID_writePathsGuard verifies that Update, Delete, AddMember, and
// DeleteMember each return an error immediately — without making any network call — when the
// GroupID field is empty.
func TestLocalGroupsEmptyGroupID_writePathsGuard(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		call func(svc *localgroups.IdsecPCloudLocalGroupsService) error
	}{
		{
			"Update",
			func(svc *localgroups.IdsecPCloudLocalGroupsService) error {
				_, err := svc.Update(&localmodels.IdsecPCloudUpdateLocalGroup{GroupID: ""})
				return err
			},
		},
		{
			"Delete",
			func(svc *localgroups.IdsecPCloudLocalGroupsService) error {
				return svc.Delete(&localmodels.IdsecPCloudDeleteLocalGroup{GroupID: ""})
			},
		},
		{
			"AddMember",
			func(svc *localgroups.IdsecPCloudLocalGroupsService) error {
				_, err := svc.AddMember(&localmodels.IdsecPCloudAddLocalGroupMember{GroupID: "", MemberName: "u"})
				return err
			},
		},
		{
			"DeleteMember",
			func(svc *localgroups.IdsecPCloudLocalGroupsService) error {
				return svc.DeleteMember(&localmodels.IdsecPCloudDeleteLocalGroupMember{GroupID: "", MemberName: "u"})
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var requests int
			svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.WriteHeader(http.StatusOK)
			})
			err := tc.call(svc)
			require.Error(t, err, "%s must reject empty GroupID", tc.name)
			require.Contains(t, err.Error(), "group ID")
			require.Zero(t, requests, "no HTTP request should be made for empty GroupID")
		})
	}
}

// TestLocalGroupsAddMember_defaultMemberType verifies that when MemberType is not supplied the
// service defaults to "Vault" in the PVWA request payload. PVWA's GroupMemberType enum has two
// values: Vault (local Vault user or provisioned LDAP user/group) and Domain (LDAP lookup via
// domainName). "Vault" is the correct default for a local-group member that already exists in
// the Vault directory.
func TestLocalGroupsAddMember_defaultMemberType(t *testing.T) {
	t.Parallel()
	var gotMemberType string
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != membersPath5 {
			http.NotFound(w, r)
			return
		}
		var body map[string]interface{}
		if err := parseJSONBody(r, &body); err == nil {
			if v, ok := body["memberType"].(string); ok {
				gotMemberType = v
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"memberName":"JDoe"}`))
	})

	_, err := svc.AddMember(&localmodels.IdsecPCloudAddLocalGroupMember{
		GroupID:    "g-5",
		MemberName: "JDoe",
		// MemberType intentionally omitted
	})
	require.NoError(t, err)
	require.Equal(t, "Vault", gotMemberType, "empty MemberType must default to Vault in the PVWA request")
}

// TestLocalGroupsAddMember_bodyDecodeFailure_returnsFallback verifies that AddMember returns the
// request fields as a fallback (rather than an error) when the 201 response body cannot be decoded.
// The 201 status already confirmed the server accepted the add.
func TestLocalGroupsAddMember_bodyDecodeFailure_returnsFallback(t *testing.T) {
	t.Parallel()
	svc := newTestLocalGroupsService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != membersPath5 {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`not-valid-json`))
	})

	member, err := svc.AddMember(&localmodels.IdsecPCloudAddLocalGroupMember{
		GroupID:    "g-5",
		MemberName: "JDoe",
		MemberType: "Vault",
	})
	require.NoError(t, err, "a 201 with unreadable body must not return an error")
	require.NotNil(t, member)
	require.Equal(t, "g-5", member.GroupID, "fallback must carry GroupID from the request")
	require.Equal(t, "JDoe", member.MemberName, "fallback must carry MemberName from the request")
}
