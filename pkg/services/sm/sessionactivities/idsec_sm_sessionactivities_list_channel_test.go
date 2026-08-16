package sessionactivities_test

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
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sm/sessionactivities"
	sessionactivitiesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sm/sessionactivities/models"
)

// List error-propagation, offset-pagination, and ListBy filter regression tests (minimal set).

func newTestSMSessionActivitiesService(t *testing.T, handler http.Handler) (*sessionactivities.IdsecSMSessionActivitiesService, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)

	client := common.NewIdsecClient("", "", "", "Authorization", nil, nil, "", false)
	client.BaseURL = srv.URL

	ispBase := &services.IdsecISPBaseService{}
	v := reflect.ValueOf(ispBase).Elem()
	clientField := v.FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	clientField.Set(reflect.ValueOf(&isp.IdsecISPServiceClient{IdsecClient: client}))

	svc := &sessionactivities.IdsecSMSessionActivitiesService{
		IdsecBaseService:    &services.IdsecBaseService{Logger: common.GlobalLogger},
		IdsecISPBaseService: ispBase,
	}
	return svc, srv.Close
}

func TestSessionActivitiesListBy_offsetPaginationAndFilter(t *testing.T) {
	t.Parallel()
	const sessionID = "sess1"
	wantPath := "/api/sessions/" + sessionID + "/activities"
	var gets []string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != wantPath {
			http.NotFound(w, r)
			return
		}
		gets = append(gets, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch r.URL.Query().Get("offset") {
		case "":
			_, _ = fmt.Fprint(w, `{"activities":[{"uuid":"a1","command":"ls -la"}],"returned_count":1,"filtered_count":2}`)
		case "1":
			_, _ = fmt.Fprint(w, `{"activities":[{"uuid":"a2","command":"whoami"}],"returned_count":1,"filtered_count":2}`)
		case "2":
			_, _ = fmt.Fprint(w, `{"activities":[],"returned_count":0,"filtered_count":2}`)
		default:
			t.Errorf("unexpected offset query: %s", r.URL.RawQuery)
		}
	})
	svc, cleanup := newTestSMSessionActivitiesService(t, h)
	t.Cleanup(cleanup)

	ch, err := svc.ListBy(&sessionactivitiesmodels.IdsecSMSessionActivitiesFilter{
		SessionID:       sessionID,
		CommandContains: "who",
	})
	require.NoError(t, err)
	require.Len(t, gets, 3, "must walk offset=0,1,2 before stopping on returned_count=0")

	var pages []*sessionactivities.IdsecSMSessionActivitiesPage
	for p := range ch {
		pages = append(pages, p)
	}
	require.Len(t, pages, 1)
	require.Len(t, pages[0].Items, 1, "client-side CommandContains filter must drop non-matching activities")
	require.Equal(t, "a2", pages[0].Items[0].UUID)
}

func TestSessionActivitiesList_midPaginationHTTPError_returnsErr(t *testing.T) {
	t.Parallel()
	const sessionID = "sess1"
	wantPath := "/api/sessions/" + sessionID + "/activities"
	var gets int
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != wantPath {
			http.NotFound(w, r)
			return
		}
		gets++
		w.Header().Set("Content-Type", "application/json")
		if gets == 1 {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"activities":[{"uuid":"a1","command":"ls"}],"returned_count":1,"filtered_count":2}`)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	})
	svc, cleanup := newTestSMSessionActivitiesService(t, h)
	t.Cleanup(cleanup)

	ch, err := svc.ListBy(&sessionactivitiesmodels.IdsecSMSessionActivitiesFilter{SessionID: sessionID})
	require.Error(t, err)
	require.Nil(t, ch)
	require.GreaterOrEqual(t, gets, 2)

	_, err = svc.CountBy(&sessionactivitiesmodels.IdsecSMSessionActivitiesFilter{SessionID: sessionID})
	require.Error(t, err, "CountBy must propagate the ListBy error")
}
