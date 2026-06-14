package pamshsafes

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshsafes/internal"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshsafes/models"
)

func newTestPamshSafesService(parts *internal.MockPVWAServiceParts) *IdsecPamshSafesService {
	return &IdsecPamshSafesService{
		IdsecBaseService:     parts.BaseService,
		IdsecPVWABaseService: parts.PVWABase,
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCreate_conflictDrainsFirstResponseBeforeGet(t *testing.T) {
	t.Parallel()

	const safeName = "existing-safe"
	var postBody *internal.TrackableBody

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/PasswordVault/API/Safes"):
			body := internal.NewTrackableBody(io.NopCloser(strings.NewReader(`{"message":"already exists"}`)))
			postBody = body
			return &http.Response{
				StatusCode: http.StatusConflict,
				Body:       body,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Request:    req,
			}, nil
		case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/PasswordVault/API/Safes"):
			require.NotNil(t, postBody)
			require.True(t, postBody.Closed(), "conflict POST body must be closed before list/get for name resolution")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{
					"value": [{"safe_url_id": "sid-1", "safe_name": %q}]
				}`, safeName))),
				Header:  http.Header{"Content-Type": []string{"application/json"}},
				Request: req,
			}, nil
		case req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/PasswordVault/API/Safes/sid-1"):
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{
					"safe_url_id": "sid-1",
					"safe_name": %q
				}`, safeName))),
				Header:  http.Header{"Content-Type": []string{"application/json"}},
				Request: req,
			}, nil
		default:
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader(`{"error":"not found"}`)),
				Request:    req,
			}, nil
		}
	}))
	svc := newTestPamshSafesService(parts)

	safe, err := svc.Create(&safesmodels.IdsecPamshAddSafe{SafeName: safeName})
	require.NoError(t, err)
	require.NotNil(t, safe)
	require.Equal(t, safeName, safe.SafeName)
}

func TestGet_resolvesSafeByName(t *testing.T) {
	t.Parallel()

	const safeName = "lookup-safe"

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/PasswordVault/API/Safes"):
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{
					"value": [{"safe_url_id": "sid-lookup", "safe_name": %q}]
				}`, safeName))),
				Header:  http.Header{"Content-Type": []string{"application/json"}},
				Request: req,
			}, nil
		case req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/PasswordVault/API/Safes/sid-lookup"):
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{
					"safe_url_id": "sid-lookup",
					"safe_name": %q
				}`, safeName))),
				Header:  http.Header{"Content-Type": []string{"application/json"}},
				Request: req,
			}, nil
		default:
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader(`{"error":"not found"}`)),
				Request:    req,
			}, nil
		}
	}))
	svc := newTestPamshSafesService(parts)

	safe, err := svc.Get(&safesmodels.IdsecPamshGetSafe{SafeName: safeName})
	require.NoError(t, err)
	require.NotNil(t, safe)
	require.Equal(t, "sid-lookup", safe.SafeID)
	require.Equal(t, safeName, safe.SafeName)
}

func TestGetMember_readOnlyPermissionSetWithExtraPermissionsResolvesToCustom(t *testing.T) {
	t.Parallel()

	const (
		safeID     = "safe-1"
		memberName = "test-user"
	)

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		memberPath := fmt.Sprintf("/PasswordVault/API/Safes/%s/Members/%s/", safeID, memberName)
		if req.Method == http.MethodGet && req.URL.Path == memberPath {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(`{
					"safe_url_id": "` + safeID + `",
					"member_name": "` + memberName + `",
					"member_type": "User",
					"permission_set": "read_only",
					"permissions": {
						"list_accounts": true,
						"use_accounts": true,
						"retrieve_accounts": true,
						"add_accounts": true
					}
				}`)),
				Header:  http.Header{"Content-Type": []string{"application/json"}},
				Request: req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader(`{"error":"not found"}`)),
			Request:    req,
		}, nil
	}))
	svc := newTestPamshSafesService(parts)

	member, err := svc.GetMember(&safesmodels.IdsecPamshGetSafeMember{
		SafeID:     safeID,
		MemberName: memberName,
	})
	require.NoError(t, err)
	require.NotNil(t, member)
	require.Equal(t, safesmodels.Custom, member.PermissionSet,
		"permission_set from PVWA is ignored when flags exceed read_only")
	require.True(t, member.Permissions.ListAccounts)
	require.True(t, member.Permissions.UseAccounts)
	require.True(t, member.Permissions.RetrieveAccounts)
	require.True(t, member.Permissions.AddAccounts)
	readOnlyPerms, ok := PermissionsForSet(safesmodels.ReadOnly)
	require.True(t, ok)
	require.NotEqual(t, readOnlyPerms, member.Permissions,
		"extra permission flags must not be treated as read_only")
}
