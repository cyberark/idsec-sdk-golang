package sessions_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sm/sessions"
	sessionsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sm/sessions/models"
)

// List error-propagation and offset-pagination regression tests (minimal set):
//   - a non-zero returned_count followed by a zero returned_count walks both pages via offset;
//   - an HTTP error on a later page surfaces as a returned error (no channel).

// newTestSMSessionsService wires an IdsecSMSessionsService directly to the given test server,
// mirroring the injection pattern used by other packages' ISP-backed service tests.
func newTestSMSessionsService(t *testing.T, handler http.Handler) (*sessions.IdsecSMSessionsService, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)

	client := common.NewIdsecClient("", "", "", "Authorization", nil, nil, "", false)
	client.BaseURL = srv.URL

	ispBase := &services.IdsecISPBaseService{}
	v := reflect.ValueOf(ispBase).Elem()
	clientField := v.FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	clientField.Set(reflect.ValueOf(&isp.IdsecISPServiceClient{IdsecClient: client}))

	svc := &sessions.IdsecSMSessionsService{
		IdsecBaseService:    &services.IdsecBaseService{Logger: common.GlobalLogger},
		IdsecISPBaseService: ispBase,
	}
	return svc, srv.Close
}

func TestSessionsList_offsetPaginationCombinesPages(t *testing.T) {
	t.Parallel()
	var gets []string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/sessions" {
			http.NotFound(w, r)
			return
		}
		gets = append(gets, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch r.URL.Query().Get("offset") {
		case "":
			_, _ = fmt.Fprint(w, `{"sessions":[{"session_id":"s1"}],"returned_count":1,"filtered_count":2}`)
		case "1":
			_, _ = fmt.Fprint(w, `{"sessions":[],"returned_count":0,"filtered_count":2}`)
		default:
			t.Errorf("unexpected offset query: %s", r.URL.RawQuery)
		}
	})
	svc, cleanup := newTestSMSessionsService(t, h)
	t.Cleanup(cleanup)

	ch, err := svc.List()
	require.NoError(t, err)
	require.Len(t, gets, 2, "must fetch a second page at offset=1 and stop once returned_count is 0")

	var sessionsOut []*sessionsmodels.IdsecSMSession
	for page := range ch {
		sessionsOut = append(sessionsOut, page.Items...)
	}
	require.Len(t, sessionsOut, 1)
	require.Equal(t, "s1", sessionsOut[0].SessionID)
}

func TestSessionsList_midPaginationHTTPError_returnsErr(t *testing.T) {
	t.Parallel()
	var gets int
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/sessions" {
			http.NotFound(w, r)
			return
		}
		gets++
		w.Header().Set("Content-Type", "application/json")
		if gets == 1 {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"sessions":[{"session_id":"s1"}],"returned_count":1,"filtered_count":2}`)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	})
	svc, cleanup := newTestSMSessionsService(t, h)
	t.Cleanup(cleanup)

	ch, err := svc.List()
	require.Error(t, err)
	require.Nil(t, ch)
	require.GreaterOrEqual(t, gets, 2)
}
