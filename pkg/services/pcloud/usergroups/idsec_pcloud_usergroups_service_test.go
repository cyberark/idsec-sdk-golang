// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package usergroups_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	pcloudint "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/internal"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/usergroups"
	usergroupsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/usergroups/models"
)

// Coverage for the user group lifecycle added on top of the pre-existing membership calls:
// the "id" -> group_id normalization on both the single-group and list decode paths, the
// list-and-filter resolution used by Get (PVWA exposes no stable GET by ID), and the status
// code handling of Create/Delete. One membership case guards against regressions in the
// member methods, which share the service's serialization helpers.

const (
	userGroupsPath   = "/PasswordVault/API/UserGroups"
	userGroupPath    = "/PasswordVault/API/UserGroups/7"
	groupMembersPath = "/PasswordVault/API/UserGroups/5/Members"
)

func newTestPCloudUserGroupsService(parts *pcloudint.MockISPServiceParts) *usergroups.IdsecPCloudUserGroupsService {
	return &usergroups.IdsecPCloudUserGroupsService{
		IdsecBaseService:    parts.BaseService,
		IdsecISPBaseService: parts.ISPBase,
	}
}

func newTestService(t *testing.T, handler http.HandlerFunc) *usergroups.IdsecPCloudUserGroupsService {
	t.Helper()
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, handler)
	t.Cleanup(cleanup)
	return newTestPCloudUserGroupsService(parts)
}

func TestUserGroupsCreate_normalizesIDIntoGroupID(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != userGroupsPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":7,"groupName":"MyGroup","description":"d","location":"\\","groupType":"Vault","vaultAuthorizations":["AddSafes","AuditUsers"]}`))
	})

	group, err := svc.Create(&usergroupsmodels.IdsecPCloudAddUserGroup{GroupName: "MyGroup"})
	require.NoError(t, err)
	require.Equal(t, 7, group.GroupID, "the API returns \"id\"; it must be normalized to group_id")
	require.Equal(t, "MyGroup", group.GroupName)
	require.Equal(t, "Vault", group.GroupType)
	// The response carries vaultAuthorizations, which no user group model declares: an
	// unmodelled field must be ignored rather than fail the decode.
}

func TestUserGroupsCreate_unexpectedStatus_returnsError(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ErrorCode":"CAWS00001E"}`))
	})

	group, err := svc.Create(&usergroupsmodels.IdsecPCloudAddUserGroup{GroupName: "MyGroup"})
	require.Error(t, err)
	require.Nil(t, group)
	require.Contains(t, err.Error(), "failed to create user group")
}

func TestUserGroupsCreate_responseWithoutID_resolvesGroupByName(t *testing.T) {
	t.Parallel()
	var listGETs int
	svc := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != userGroupsPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			// No "id": some PVWA versions do not echo the new group's identifier back.
			_, _ = w.Write([]byte(`{"groupName":"MyGroup","location":"\\"}`))
		case http.MethodGet:
			listGETs++
			require.Equal(t, "MyGroup", r.URL.Query().Get("search"))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"value":[{"id":7,"groupName":"MyGroup","groupType":"Vault"}]}`))
		default:
			http.NotFound(w, r)
		}
	})

	group, err := svc.Create(&usergroupsmodels.IdsecPCloudAddUserGroup{GroupName: "MyGroup"})
	require.NoError(t, err)
	require.Equal(t, 7, group.GroupID, "an ID-less create response must be resolved through the list endpoint")
	require.Equal(t, "Vault", group.GroupType)
	require.Equal(t, 1, listGETs)
}

func TestUserGroupsCreate_responseWithoutIDAndGroupNotListed_returnsError(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != userGroupsPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"groupName":"MyGroup"}`))
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"value":[]}`))
		default:
			http.NotFound(w, r)
		}
	})

	group, err := svc.Create(&usergroupsmodels.IdsecPCloudAddUserGroup{GroupName: "MyGroup"})
	require.Error(t, err, "a group without a usable ID cannot be deleted or imported later, so it must not be returned")
	require.Nil(t, group)
	require.Contains(t, err.Error(), "not found")
}

func TestUserGroupsGet_byName_matchesCaseInsensitively(t *testing.T) {
	t.Parallel()
	var searches []string
	svc := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != userGroupsPath {
			http.NotFound(w, r)
			return
		}
		searches = append(searches, r.URL.Query().Get("search"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[{"id":3,"groupName":"Other"},{"id":7,"groupName":"MyGroup"}]}`))
	})

	group, err := svc.Get(&usergroupsmodels.IdsecPCloudGetUserGroup{GroupName: "mygroup"})
	require.NoError(t, err)
	require.Equal(t, 7, group.GroupID)
	require.Equal(t, "MyGroup", group.GroupName)
	require.Equal(t, []string{"mygroup"}, searches, "the group name must narrow the server-side search")
}

func TestUserGroupsGet_byIDOnly_resolvesThroughList(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != userGroupsPath {
			http.NotFound(w, r)
			return
		}
		require.Empty(t, r.URL.Query().Get("search"), "no name was supplied, so nothing to search on")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[{"id":3,"groupName":"Other"},{"id":7,"groupName":"MyGroup"}]}`))
	})

	group, err := svc.Get(&usergroupsmodels.IdsecPCloudGetUserGroup{GroupID: 7})
	require.NoError(t, err)
	require.Equal(t, "MyGroup", group.GroupName)
}

func TestUserGroupsGet_notFound_returnsError(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != userGroupsPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[{"id":3,"groupName":"Other"}]}`))
	})

	group, err := svc.Get(&usergroupsmodels.IdsecPCloudGetUserGroup{GroupName: "MyGroup"})
	require.Error(t, err)
	require.Nil(t, group)
	require.Contains(t, err.Error(), "user group with name 'MyGroup' not found")
}

func TestUserGroupsGet_nameMatchesButIDDoesNot_reportsBothInError(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != userGroupsPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[{"id":3,"groupName":"MyGroup"}]}`))
	})

	group, err := svc.Get(&usergroupsmodels.IdsecPCloudGetUserGroup{GroupName: "MyGroup", GroupID: 7})
	require.Error(t, err)
	require.Nil(t, group)
	require.Contains(t, err.Error(), "user group with name 'MyGroup' and ID '7' not found",
		"reporting only one of the two criteria hides which of them failed to match")
}

func TestUserGroupsGet_withoutIDOrName_returnsErrorWithoutRequest(t *testing.T) {
	t.Parallel()
	var requests int
	svc := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	})

	group, err := svc.Get(&usergroupsmodels.IdsecPCloudGetUserGroup{})
	require.Error(t, err)
	require.Nil(t, group)
	require.Zero(t, requests, "the input is unusable, so no call must be made")
}

func TestUserGroupsList_paginatesAndNormalizesEachItem(t *testing.T) {
	t.Parallel()
	var listGETs int
	svc := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != userGroupsPath {
			http.NotFound(w, r)
			return
		}
		listGETs++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if listGETs == 1 {
			next := "http://" + r.Host + userGroupsPath + "?page=2"
			_, _ = fmt.Fprintf(w, `{"value":[{"id":3,"groupName":"G3"}],"nextLink":%q}`, next)
			return
		}
		_, _ = w.Write([]byte(`{"value":[{"id":7,"groupName":"G7"}]}`))
	})

	pages, err := svc.List()
	require.NoError(t, err)
	var groups []*usergroupsmodels.IdsecPCloudUserGroup
	for page := range pages {
		groups = append(groups, page.Items...)
	}
	require.Len(t, groups, 2)
	require.Equal(t, 3, groups[0].GroupID)
	require.Equal(t, 7, groups[1].GroupID)
	require.Equal(t, 2, listGETs, "the second page must be fetched from nextLink")
}

func TestUserGroupsList_httpError_returnsErrorAndNoChannel(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	})

	pages, err := svc.List()
	require.Error(t, err)
	require.Nil(t, pages)
}

func TestUserGroupsUpdate_putsToGroupURLWithoutGroupIDInBody(t *testing.T) {
	t.Parallel()
	var body map[string]interface{}
	svc := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != userGroupPath {
			http.NotFound(w, r)
			return
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":7,"groupName":"Renamed","description":"new","location":"\\"}`))
	})

	group, err := svc.Update(&usergroupsmodels.IdsecPCloudUpdateUserGroup{
		GroupID:     7,
		GroupName:   "Renamed",
		Description: "new",
		Location:    "\\",
	})
	require.NoError(t, err)
	require.Equal(t, 7, group.GroupID, "the API returns \"id\"; it must be normalized to group_id")
	require.Equal(t, "Renamed", group.GroupName)
	require.NotContains(t, body, "groupId", "the group ID travels in the URL path, not the body")
	require.Equal(t, "Renamed", body["groupName"])
}

func TestUserGroupsUpdate_unexpectedStatus_returnsError(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"ErrorCode":"CAWS00002E"}`))
	})

	group, err := svc.Update(&usergroupsmodels.IdsecPCloudUpdateUserGroup{GroupID: 7, GroupName: "Renamed"})
	require.Error(t, err)
	require.Nil(t, group)
	require.Contains(t, err.Error(), "failed to update user group")
}

func TestUserGroupsDelete_acceptsNoContentAndOK(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusNoContent, http.StatusOK} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			svc := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete || r.URL.Path != userGroupPath {
					http.NotFound(w, r)
					return
				}
				w.WriteHeader(status)
			})

			require.NoError(t, svc.Delete(&usergroupsmodels.IdsecPCloudDeleteUserGroup{GroupID: 7}))
		})
	}
}

func TestUserGroupsDelete_unexpectedStatus_returnsError(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	})

	err := svc.Delete(&usergroupsmodels.IdsecPCloudDeleteUserGroup{GroupID: 7})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to delete user group")
}

func TestUserGroupsAddMember_sendsMemberNameAsMemberID(t *testing.T) {
	t.Parallel()
	var body map[string]interface{}
	svc := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != groupMembersPath {
			http.NotFound(w, r)
			return
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":11,"memberType":"Vault"}`))
	})

	member, err := svc.AddMember(&usergroupsmodels.IdsecPCloudAddUserGroupMember{
		GroupID:    5,
		MemberName: "jdoe",
		MemberType: "Vault",
	})
	require.NoError(t, err)
	require.Equal(t, "jdoe", body["memberId"],
		"the wire field is named memberId but carries the member's name, not a number")
	require.NotContains(t, body, "memberName")
	require.NotContains(t, body, "groupId", "the group ID addresses the route, not the body")
	require.Equal(t, 5, member.GroupID)
	require.Equal(t, "jdoe", member.MemberName)
	require.Equal(t, 11, member.MemberID, "the numeric member ID is reported by the Vault, not supplied")
	require.Equal(t, "Vault", member.MemberType)
}

func TestUserGroupsAddMember_emptyResponseBody_reconstructsFromRequest(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != groupMembersPath {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})

	member, err := svc.AddMember(&usergroupsmodels.IdsecPCloudAddUserGroupMember{
		GroupID:    5,
		MemberName: "jdoe",
		MemberType: "Vault",
	})
	require.NoError(t, err, "the membership was created, so an unreadable body must not fail the call")
	require.Equal(t, "jdoe", member.MemberName)
	require.Zero(t, member.MemberID, "no numeric ID was reported, so none can be claimed")
}

// The client escapes each path segment on the way out, so a member name with a space or a
// backslash must arrive at the server intact rather than doubly encoded.
func TestUserGroupsDeleteMember_putsMemberNameInPath(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name       string
		memberName string
		wantPath   string
	}{
		{"plain", "jdoe", groupMembersPath + "/jdoe"},
		{"with space", "Artur P", groupMembersPath + "/Artur P"},
		{"with slash", "dom\\jdoe", groupMembersPath + "/dom\\jdoe"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var gotPath string
			svc := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					http.NotFound(w, r)
					return
				}
				// r.URL.Path is already decoded, so this asserts the round trip rather than
				// the escaping itself.
				gotPath = r.URL.Path
				w.WriteHeader(http.StatusNoContent)
			})

			require.NoError(t, svc.DeleteMember(&usergroupsmodels.IdsecPCloudDeleteUserGroupMember{
				GroupID:    5,
				MemberName: testCase.memberName,
			}))
			require.Equal(t, testCase.wantPath, gotPath)
		})
	}
}

func TestUserGroupsDeleteMember_unexpectedStatus_returnsError(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"ErrorCode":"CAWS00003E"}`))
	})

	err := svc.DeleteMember(&usergroupsmodels.IdsecPCloudDeleteUserGroupMember{GroupID: 5, MemberName: "jdoe"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to delete user group member")
}
