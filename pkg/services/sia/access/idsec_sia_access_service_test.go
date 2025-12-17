package access

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

func httpResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func newServiceWithGet(
	fn func(ctx context.Context, path string, params map[string]string) (*http.Response, error),
) *IdsecSIAAccessService {
	return &IdsecSIAAccessService{
		IdsecBaseService: &services.IdsecBaseService{
			Logger: common.GlobalLogger,
		},
		doGet: fn,
	}
}

func TestListConnectors_Success(t *testing.T) {
	okJSON := `{
	  "connectors": [
	    {"id":"c-1","name":"alpha"},
	    {"id":"c-2","name":"beta"}
	  ],
	  "total": 2
	}`

	var gotPath string
	svc := newServiceWithGet(func(ctx context.Context, path string, params map[string]string) (*http.Response, error) {
		gotPath = path
		require.Nil(t, params)
		return httpResp(http.StatusOK, okJSON), nil
	})

	got, err := svc.ListConnectors()
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, connectorsURL, gotPath)
}

func TestListConnectors_TransportError(t *testing.T) {
	svc := newServiceWithGet(func(ctx context.Context, path string, params map[string]string) (*http.Response, error) {
		return nil, fmt.Errorf("network down")
	})

	got, err := svc.ListConnectors()
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "network down")
}

func TestListConnectors_Non200Status(t *testing.T) {
	svc := newServiceWithGet(func(ctx context.Context, path string, params map[string]string) (*http.Response, error) {
		return httpResp(http.StatusInternalServerError, `{"error":"boom"}`), nil
	})

	got, err := svc.ListConnectors()
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "failed to list connectors")
}

func TestListConnectors_BadJSON(t *testing.T) {
	svc := newServiceWithGet(func(ctx context.Context, path string, params map[string]string) (*http.Response, error) {
		return httpResp(http.StatusOK, `not-json`), nil
	})

	got, err := svc.ListConnectors()
	require.Error(t, err)
	require.Nil(t, got)
}

func TestListConnectors_DecodeMismatch(t *testing.T) {
	svc := newServiceWithGet(func(ctx context.Context, path string, params map[string]string) (*http.Response, error) {
		return httpResp(http.StatusOK, `{"connectors":"not-a-list"}`), nil
	})

	got, err := svc.ListConnectors()
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Zero(t, got.Count)
	require.Len(t, got.Items, 0)
}
