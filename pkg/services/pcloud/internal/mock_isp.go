// Package internal holds small test helpers for pCloud packages (same idea as pamshaccounts/internal).
package internal

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"unsafe"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

// MockISPServiceParts holds injected ISP client dependencies for tests (same wiring idea as pamshaccounts/internal.MockPVWAServiceParts).
type MockISPServiceParts struct {
	BaseService *services.IdsecBaseService
	ISPBase     *services.IdsecISPBaseService
}

// NewMockISPServiceParts builds service parts with the given ISP API base URL.
func NewMockISPServiceParts(baseURL string) *MockISPServiceParts {
	client := common.NewIdsecClient("", "", "", "Authorization", nil, nil, "", false)
	client.BaseURL = baseURL

	ispBase := &services.IdsecISPBaseService{}
	v := reflect.ValueOf(ispBase).Elem()
	clientField := v.FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	clientField.Set(reflect.ValueOf(&isp.IdsecISPServiceClient{IdsecClient: client}))

	return &MockISPServiceParts{
		BaseService: &services.IdsecBaseService{Logger: common.GlobalLogger},
		ISPBase:     ispBase,
	}
}

// SetupMockISPServiceParts starts an httptest server with handler and returns parts wired to its URL,
// plus cleanup (same pattern as pamshaccounts/internal.SetupMockPVWAServiceParts).
func SetupMockISPServiceParts(t *testing.T, handler http.Handler) (*MockISPServiceParts, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	parts := NewMockISPServiceParts(srv.URL)
	return parts, srv.Close
}
