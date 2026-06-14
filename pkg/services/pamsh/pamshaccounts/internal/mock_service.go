// Package internal provides test helpers for the pamsh accounts service package.
package internal

import (
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	pvwaclient "github.com/cyberark/idsec-sdk-golang/pkg/common/pvwa"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

// TrackableBody wraps an io.ReadCloser and records when Close is called.
type TrackableBody struct {
	io.ReadCloser
	closed atomic.Bool
}

// NewTrackableBody wraps rc and tracks Close calls.
func NewTrackableBody(rc io.ReadCloser) *TrackableBody {
	return &TrackableBody{ReadCloser: rc}
}

// Close closes the underlying reader and marks this body as closed.
func (b *TrackableBody) Close() error {
	b.closed.Store(true)
	if b.ReadCloser == nil {
		return nil
	}
	return b.ReadCloser.Close()
}

// Closed reports whether Close has been called.
func (b *TrackableBody) Closed() bool {
	return b.closed.Load()
}

// MockPVWAServiceParts holds injected PVWA client dependencies for tests.
type MockPVWAServiceParts struct {
	BaseService *services.IdsecBaseService
	PVWABase    *services.IdsecPVWABaseService
}

// SetupMockPVWAServiceParts wires an IdsecPVWABaseService to an httptest server.
func SetupMockPVWAServiceParts(t *testing.T, handler http.Handler) (*MockPVWAServiceParts, func()) {
	t.Helper()

	testServer := httptest.NewServer(handler)
	parts := NewMockPVWAServiceParts(testServer.URL)
	return parts, testServer.Close
}

// NewMockPVWAServiceParts builds service parts with the given PVWA base URL.
func NewMockPVWAServiceParts(baseURL string) *MockPVWAServiceParts {
	client := common.NewIdsecClient("", "", "", "Authorization", nil, nil, "", false)
	client.BaseURL = baseURL

	pvwaBase := &services.IdsecPVWABaseService{}
	v := reflect.ValueOf(pvwaBase).Elem()
	clientField := v.FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	clientField.Set(reflect.ValueOf(&pvwaclient.IdsecPVWAServiceClient{IdsecClient: client}))

	return &MockPVWAServiceParts{
		BaseService: &services.IdsecBaseService{
			Logger: common.GlobalLogger,
		},
		PVWABase: pvwaBase,
	}
}

// SetupMockPVWAServicePartsWithTransport builds service parts with a custom HTTP RoundTripper.
func SetupMockPVWAServicePartsWithTransport(t *testing.T, transport http.RoundTripper) *MockPVWAServiceParts {
	t.Helper()

	parts := NewMockPVWAServiceParts("http://pvwa-mock.local")
	InjectHTTPTransport(t, parts.PVWABase, transport)
	return parts
}

// InjectHTTPTransport sets a custom RoundTripper on the PVWA HTTP client.
func InjectHTTPTransport(t *testing.T, pvwaBase *services.IdsecPVWABaseService, transport http.RoundTripper) {
	t.Helper()

	v := reflect.ValueOf(pvwaBase).Elem()
	clientField := v.FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	pvwaServiceClient := clientField.Interface().(*pvwaclient.IdsecPVWAServiceClient)
	idsecClient := pvwaServiceClient.IdsecClient

	icv := reflect.ValueOf(idsecClient).Elem()
	httpClientField := icv.FieldByName("client")
	httpClientField = reflect.NewAt(httpClientField.Type(), unsafe.Pointer(httpClientField.UnsafeAddr())).Elem()
	httpClient := httpClientField.Interface().(*http.Client)
	httpClient.Transport = transport
}
