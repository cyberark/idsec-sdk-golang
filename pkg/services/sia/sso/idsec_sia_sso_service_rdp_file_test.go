package sso

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"unsafe"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	ssomodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/validation"
)

// Shaped after adb-customer-sso-service: "full address" is the tenant gateway, while the
// target and the vaulted account ID travel in the connection string carried by "username".
const testRDPFileText = `full address:s:mytenant.rdp.cyberark.cloud
username:s:secureaccess /i myuser@cyberark.cloud.12345 /s mytenant /d mydomain.com /a mymachine.mydomain.com /u myuser /v 10_10
gatewayhostname:s:mytenant.rdp.cyberark.cloud:443
gatewayaccesstoken:s:secureaccess
gatewaycredentialssource:i:5
gatewayusagemethod:i:1
gatewayprofileusagemethod:i:1
auto connect:i:1
smart sizing:i:1`

type capturedRequests struct {
	mu     sync.Mutex
	count  int
	bodies []map[string]interface{}
}

func (c *capturedRequests) requestCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

func (c *capturedRequests) tokenParameters(t *testing.T) map[string]interface{} {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	require.Len(t, c.bodies, 1, "expected exactly one acquire-token request")
	params, ok := c.bodies[0]["token_parameters"].(map[string]interface{})
	require.True(t, ok, "token_parameters missing from request body: %v", c.bodies[0])
	return params
}

// Callers leave AllowCaching false, which keeps loadFromCache and saveToCache out of the
// flow, so no keyring or profile loader is needed.
func setupMockSSOService(t *testing.T) (*IdsecSIASSOService, *capturedRequests) {
	t.Helper()

	captured := &capturedRequests{}
	responseBody, err := json.Marshal(map[string]interface{}{
		"token":    map[string]interface{}{"text": testRDPFileText},
		"metadata": map[string]interface{}{},
	})
	require.NoError(t, err)

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, readErr := io.ReadAll(r.Body)
		body := map[string]interface{}{}
		if readErr == nil {
			_ = json.Unmarshal(raw, &body)
		}

		captured.mu.Lock()
		captured.count++
		captured.bodies = append(captured.bodies, body)
		captured.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(responseBody)
	}))
	t.Cleanup(testServer.Close)

	client := common.NewIdsecClient("", "", "", "Authorization", nil, nil, "", false)
	client.BaseURL = testServer.URL

	ispBase := &services.IdsecISPBaseService{}
	clientField := reflect.ValueOf(ispBase).Elem().FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	clientField.Set(reflect.ValueOf(&isp.IdsecISPServiceClient{IdsecClient: client}))

	return &IdsecSIASSOService{
		IdsecBaseService:    &services.IdsecBaseService{Logger: common.GlobalLogger},
		IdsecISPBaseService: ispBase,
	}, captured
}

// The SSO service drops a token parameter it does not recognise instead of failing the
// request, so only an assertion on the request body catches a misspelled key.
func TestShortLivedRdpFile_VaultedAccountIDTokenParameter(t *testing.T) {
	t.Run("sent_when_given", func(t *testing.T) {
		service, captured := setupMockSSOService(t)

		folder := t.TempDir()
		require.NoError(t, service.ShortLivedRdpFile(&ssomodels.IdsecSIASSOGetShortLivedRDPFile{
			Folder:           folder,
			TargetAddress:    "mymachine.mydomain.com",
			TargetUser:       "myuser",
			VaultedAccountID: "10_10",
		}))

		require.Equal(t, "10_10", captured.tokenParameters(t)["vaultedAccountID"])

		written, err := os.ReadFile(filepath.Join(folder, "sia _a mymachine.mydomain.com.rdp"))
		require.NoError(t, err)
		require.Equal(t, testRDPFileText, string(written))
	})

	t.Run("omitted_when_empty", func(t *testing.T) {
		service, captured := setupMockSSOService(t)

		require.NoError(t, service.ShortLivedRdpFile(&ssomodels.IdsecSIASSOGetShortLivedRDPFile{
			Folder:        t.TempDir(),
			TargetAddress: "mymachine.mydomain.com",
			TargetUser:    "myuser",
		}))

		require.NotContains(t, captured.tokenParameters(t), "vaultedAccountID")
	})
}

// Guards the ValidateStruct call in ShortLivedRdpFile, which the model tests cannot: they
// call ValidateStruct themselves and would keep passing if the service stopped doing so.
func TestShortLivedRdpFile_RejectsInvalidRequestBeforeTheAPICall(t *testing.T) {
	folder := t.TempDir()

	tests := map[string]struct {
		request *ssomodels.IdsecSIASSOGetShortLivedRDPFile
		field   string
		rule    string
	}{
		"malformed_vaulted_account_id": {
			request: &ssomodels.IdsecSIASSOGetShortLivedRDPFile{
				Folder:           folder,
				TargetAddress:    "mymachine.mydomain.com",
				TargetUser:       "myuser",
				VaultedAccountID: "abc",
			},
			field: "vaulted_account_id",
			rule:  "regexp",
		},
		"vaulted_account_id_without_target_user": {
			request: &ssomodels.IdsecSIASSOGetShortLivedRDPFile{
				Folder:           folder,
				TargetAddress:    "mymachine.mydomain.com",
				VaultedAccountID: "10_10",
			},
			field: "vaulted_account_id",
			rule:  "excluded_without",
		},
		"missing_target_address": {
			request: &ssomodels.IdsecSIASSOGetShortLivedRDPFile{
				Folder:     folder,
				TargetUser: "myuser",
			},
			field: "target_address",
			rule:  "required",
		},
		// Folder was tagged required long before anything read that tag on this path.
		"missing_folder": {
			request: &ssomodels.IdsecSIASSOGetShortLivedRDPFile{
				TargetAddress: "mymachine.mydomain.com",
				TargetUser:    "myuser",
			},
			field: "folder",
			rule:  "required",
		},
	}
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			service, captured := setupMockSSOService(t)

			err := service.ShortLivedRdpFile(test.request)

			require.Error(t, err)
			var fieldErrors validator.ValidationErrors
			require.ErrorAs(t, err, &fieldErrors)
			require.Len(t, fieldErrors, 1)
			require.Equal(t, test.field, validation.FieldPath(fieldErrors[0]))
			require.Equal(t, test.rule, fieldErrors[0].Tag())
			require.Zero(t, captured.requestCount(), "an invalid request must not reach the token endpoint")
		})
	}
}
