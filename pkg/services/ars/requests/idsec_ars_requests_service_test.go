package requests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	requestsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/ars/requests/models"
)

const requestFormsResponse = `{
	"requestForms": [{
		"targetCategory": "CLOUD_CONSOLE",
		"requestType": "ON_DEMAND",
		"requestForm": {"questions": [
			{"key": "location_type", "required": true, "title": "Location Type", "valueType": "CHOICE", "valueChoices": ["AWS", "GCP", "Azure"]},
			{"key": "org_id", "required": {"operator": "OR", "conditions": [
				{"name": "regex_condition", "key": "location_type", "condition": "^(GCP|Azure)$"}
			]}, "valueType": "STRING", "validators": [{"name": "type_checker_validator"}]},
			{"key": "priority", "required": true, "default": "Medium", "valueType": "CHOICE", "valueChoices": ["High", "Medium", "Low"]}
		]}
	}]
}`

func accessRequestJSON(id, state, result string) string {
	return fmt.Sprintf(`{"requestId":%q,"targetCategory":"VM","requestState":%q,"requestResult":%q,`+
		`"requestDetails":{"targetHost":"10.0.0.1"},"createdBy":"user","createdAt":"2026-01-01T00:00:00Z",`+
		`"updatedBy":"user","updatedAt":"2026-01-01T00:00:00Z"}`, id, state, result)
}

type recordedRequest struct {
	Method string
	Path   string
	Query  map[string]string
	Body   map[string]interface{}
}

// newTestService wires an IdsecARSRequestsService to a test server and records every request it receives.
func newTestService(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (*IdsecARSRequestsService, *[]recordedRequest) {
	t.Helper()
	var mu sync.Mutex
	var recorded []recordedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := recordedRequest{Method: r.Method, Path: r.URL.Path, Query: map[string]string{}}
		for k := range r.URL.Query() {
			rec.Query[k] = r.URL.Query().Get(k)
		}
		if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
			require.NoError(t, json.Unmarshal(raw, &rec.Body))
		}
		mu.Lock()
		recorded = append(recorded, rec)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		handler(w, r)
	}))
	t.Cleanup(srv.Close)

	client := common.NewIdsecClient("", "", "", "Authorization", nil, nil, "", false)
	client.BaseURL = srv.URL
	ispBase := &services.IdsecISPBaseService{}
	clientField := reflect.ValueOf(ispBase).Elem().FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	clientField.Set(reflect.ValueOf(&isp.IdsecISPServiceClient{IdsecClient: client}))

	svc := &IdsecARSRequestsService{
		IdsecBaseService:    &services.IdsecBaseService{Logger: common.GlobalLogger},
		IdsecISPBaseService: ispBase,
	}
	return svc, &recorded
}

func respond(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	_, _ = fmt.Fprint(w, body)
}

func TestServiceConfig(t *testing.T) {
	config := (&IdsecARSRequestsService{}).ServiceConfig()
	assert.Equal(t, "ars-requests", config.ServiceName)
	assert.Equal(t, []string{"isp"}, config.RequiredAuthenticatorNames)
}

func TestActionsMatchServiceMethods(t *testing.T) {
	actionMethods := map[string]string{
		"submit":             "Submit",
		"cancel":             "Cancel",
		"finalize":           "Finalize",
		"list":               "List",
		"list-by":            "ListBy",
		"get":                "Get",
		"stats":              "Stats",
		"list-request-forms": "ListRequestForms",
	}
	config := (&IdsecARSRequestsService{}).ServiceConfig()
	require.Len(t, config.ActionSchemas, len(actionMethods))
	serviceValue := reflect.ValueOf(&IdsecARSRequestsService{})
	for action, methodName := range actionMethods {
		schema, registered := config.ActionSchemas[action]
		require.True(t, registered, "action %q is not registered", action)
		method := serviceValue.MethodByName(methodName)
		require.True(t, method.IsValid(), "action %q names missing method %s", action, methodName)
		if schema == nil {
			assert.Equal(t, 0, method.Type().NumIn(), "%s must take no argument", methodName)
			continue
		}
		require.Equal(t, 1, method.Type().NumIn())
		assert.Equal(t, reflect.TypeOf(schema), method.Type().In(0), "%s must take the schema of %q", methodName, action)
	}
}

func TestARSServiceName(t *testing.T) {
	assert.Equal(t, "uar", arsServiceName(commonmodels.Prod))
	assert.Equal(t, "ars", arsServiceName(commonmodels.AwsEnv("dev")))
	assert.Equal(t, "ars", arsServiceName(commonmodels.GovProd))
}

func TestSortQueryParam(t *testing.T) {
	tests := []struct {
		name     string
		sort     []requestsmodels.IdsecARSSortQuery
		expected string
	}{
		{"nil", nil, ""},
		{"single_with_direction", []requestsmodels.IdsecARSSortQuery{{Field: "created_at", Direction: requestsmodels.SortDirectionDesc}}, "created_at desc"},
		{"single_without_direction", []requestsmodels.IdsecARSSortQuery{{Field: "name"}}, "name"},
		{"multiple", []requestsmodels.IdsecARSSortQuery{
			{Field: "created_at", Direction: requestsmodels.SortDirectionDesc},
			{Field: "name", Direction: requestsmodels.SortDirectionAsc},
		}, "created_at desc,name asc"},
		{"skips_missing_field", []requestsmodels.IdsecARSSortQuery{
			{Direction: requestsmodels.SortDirectionDesc},
			{Field: "name", Direction: requestsmodels.SortDirectionAsc},
		}, "name asc"},
		{"all_missing_fields", []requestsmodels.IdsecARSSortQuery{{Direction: requestsmodels.SortDirectionDesc}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, sortQueryParam(tt.sort))
		})
	}
}

func TestListQueryFromFilter(t *testing.T) {
	assert.Equal(t, map[string]string{"extended": "false", "limit": "1000"}, listQueryFromFilter(nil))
	assert.Equal(t, map[string]string{
		"extended": "true",
		"limit":    "50",
		"offset":   "10",
		"sort":     "created_at desc",
		"filter":   "requestState eq 'PENDING'",
	}, listQueryFromFilter(&requestsmodels.IdsecARSFilter{
		Filter:   "requestState eq 'PENDING'",
		Extended: true,
		Offset:   10,
		Limit:    50,
		Sort:     []requestsmodels.IdsecARSSortQuery{{Field: "created_at", Direction: requestsmodels.SortDirectionDesc}},
	}))
}

func TestTaskStatus(t *testing.T) {
	tests := []struct {
		state    requestsmodels.IdsecARSAccessRequestState
		result   requestsmodels.IdsecARSAccessRequestResult
		expected pollStatus
	}{
		{requestsmodels.RequestStateFinished, requestsmodels.RequestResultApproved, pollStatusSuccess},
		{requestsmodels.RequestStateFinished, requestsmodels.RequestResultRejected, pollStatusSuccess},
		{requestsmodels.RequestStateFinished, requestsmodels.RequestResultCanceled, pollStatusSuccess},
		{requestsmodels.RequestStateFinished, requestsmodels.RequestResultFailed, pollStatusFailed},
		{requestsmodels.RequestStateFinished, requestsmodels.RequestResultUnknown, pollStatusFailed},
		{requestsmodels.RequestStateExpired, requestsmodels.RequestResultUnknown, pollStatusFailed},
		{requestsmodels.RequestStatePending, requestsmodels.RequestResultUnknown, pollStatusPending},
		{requestsmodels.RequestStateStarting, requestsmodels.RequestResultUnknown, pollStatusInProgress},
		{requestsmodels.RequestStateRunning, requestsmodels.RequestResultUnknown, pollStatusInProgress},
		{"BOGUS", requestsmodels.RequestResultUnknown, pollStatusFailed},
	}
	for _, tt := range tests {
		t.Run(strings.ToLower(fmt.Sprintf("%s_%s", tt.state, tt.result)), func(t *testing.T) {
			assert.Equal(t, tt.expected, taskStatus(&requestsmodels.IdsecARSAccessRequest{RequestState: tt.state, RequestResult: tt.result}))
		})
	}
}

func TestGet(t *testing.T) {
	svc, recorded := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, accessRequestJSON("req-1", "PENDING", "UNKNOWN"))
	})
	request, err := svc.Get(&requestsmodels.IdsecARSGetAccessRequest{RequestID: "req-1"})
	require.NoError(t, err)
	assert.Equal(t, "/api/workflows/requests/req-1", (*recorded)[0].Path)
	assert.Equal(t, "req-1", request.RequestID)
	assert.Equal(t, requestsmodels.TargetCategoryVM, request.TargetCategory)
	assert.Equal(t, requestsmodels.RequestStatePending, request.RequestState)
	assert.Equal(t, map[string]interface{}{"target_host": "10.0.0.1"}, request.RequestDetails)
}

func TestGet_fallsBackToSurveyInputAndDefaultsResult(t *testing.T) {
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, `{"requestId":"req-1","targetCategory":"VM","requestState":"RUNNING","requestSurveyInput":{"reason":"x"}}`)
	})
	request, err := svc.Get(&requestsmodels.IdsecARSGetAccessRequest{RequestID: "req-1"})
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"reason": "x"}, request.RequestDetails)
	assert.Equal(t, requestsmodels.RequestResultUnknown, request.RequestResult)
}

func TestGet_errorStatus(t *testing.T) {
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusNotFound, `{"message":"not found"}`)
	})
	_, err := svc.Get(&requestsmodels.IdsecARSGetAccessRequest{RequestID: "missing"})
	require.ErrorContains(t, err, "failed to get access request - [404]")
}

func TestSubmit_sendsBodyAndDropsAssociationWithoutID(t *testing.T) {
	svc, recorded := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, accessRequestJSON("req-1", "STARTING", "UNKNOWN"))
	})
	request, err := svc.Submit(&requestsmodels.IdsecARSSubmitAccessRequest{
		TargetCategory: requestsmodels.TargetCategoryVM,
		RequestDetails: map[string]interface{}{"target_host": "10.0.0.1"},
		Association:    map[string]interface{}{"association_type": "policy"},
	})
	require.NoError(t, err)
	assert.Equal(t, "req-1", request.RequestID)
	rec := (*recorded)[0]
	assert.Equal(t, http.MethodPost, rec.Method)
	assert.Equal(t, "/api/workflows/requests", rec.Path)
	assert.Equal(t, map[string]interface{}{
		"target_category":     "VM",
		"request_type":        "ON_DEMAND",
		"request_details":     map[string]interface{}{"target_host": "10.0.0.1"},
		"association":         nil,
		"wait_until_finished": false,
	}, rec.Body)
}

func TestSubmit_keepsAssociationWithID(t *testing.T) {
	svc, recorded := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, accessRequestJSON("req-1", "STARTING", "UNKNOWN"))
	})
	_, err := svc.Submit(&requestsmodels.IdsecARSSubmitAccessRequest{
		TargetCategory: requestsmodels.TargetCategoryCloudConsole,
		RequestType:    requestsmodels.RequestTypeDualControl,
		Association:    map[string]interface{}{"association_id": "policy-1"},
	})
	require.NoError(t, err)
	body := (*recorded)[0].Body
	assert.Equal(t, "CLOUD_CONSOLE", body["target_category"])
	assert.Equal(t, "DUAL_CONTROL", body["request_type"])
	assert.Equal(t, map[string]interface{}{"association_id": "policy-1"}, body["association"])
}

func TestSubmit_pollsUntilPending(t *testing.T) {
	pollInterval = time.Millisecond
	var gets int
	svc, _ := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			respond(w, http.StatusOK, accessRequestJSON("req-1", "STARTING", "UNKNOWN"))
			return
		}
		gets++
		state := "RUNNING"
		if gets >= 2 {
			state = "PENDING"
		}
		respond(w, http.StatusOK, accessRequestJSON("req-1", state, "UNKNOWN"))
	})
	request, err := svc.Submit(&requestsmodels.IdsecARSSubmitAccessRequest{
		Poll:           true,
		TargetCategory: requestsmodels.TargetCategoryVM,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, gets)
	assert.Equal(t, requestsmodels.RequestStatePending, request.RequestState)
}

func TestCancel_sendsReasonAndPollsUntilFinished(t *testing.T) {
	pollInterval = time.Millisecond
	svc, recorded := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			respond(w, http.StatusOK, accessRequestJSON("req-1", "RUNNING", "UNKNOWN"))
			return
		}
		respond(w, http.StatusOK, accessRequestJSON("req-1", "FINISHED", "CANCELED"))
	})
	request, err := svc.Cancel(&requestsmodels.IdsecARSCancelAccessRequest{
		Poll:         true,
		RequestID:    "req-1",
		CancelReason: "no longer needed",
	})
	require.NoError(t, err)
	assert.Equal(t, requestsmodels.RequestResultCanceled, request.RequestResult)
	rec := (*recorded)[0]
	assert.Equal(t, "/api/workflows/requests/req-1/cancel", rec.Path)
	assert.Equal(t, map[string]interface{}{"cancel_reason": "no longer needed"}, rec.Body)
}

func TestFinalize_sendsBodyWithoutPolling(t *testing.T) {
	svc, recorded := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, accessRequestJSON("req-1", "RUNNING", "APPROVED"))
	})
	request, err := svc.Finalize(&requestsmodels.IdsecARSFinalizeAccessRequest{
		RequestID:          "req-1",
		Result:             string(requestsmodels.RequestResultRejected),
		FinalizationReason: "not allowed",
	})
	require.NoError(t, err)
	assert.Equal(t, requestsmodels.RequestStateRunning, request.RequestState)
	require.Len(t, *recorded, 1)
	rec := (*recorded)[0]
	assert.Equal(t, "/api/workflows/requests/req-1/finalize", rec.Path)
	assert.Equal(t, map[string]interface{}{
		"result":              "REJECTED",
		"request_details":     nil,
		"finalization_reason": "not allowed",
		"wait_until_finished": false,
	}, rec.Body)
}

func TestFinalize_pollFailsOnFailedRequest(t *testing.T) {
	pollInterval = time.Millisecond
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, accessRequestJSON("req-1", "EXPIRED", "UNKNOWN"))
	})
	_, err := svc.Finalize(&requestsmodels.IdsecARSFinalizeAccessRequest{
		Poll:      true,
		RequestID: "req-1",
		Result:    string(requestsmodels.RequestResultApproved),
	})
	require.ErrorContains(t, err, "access request [req-1] failed")
}

func TestSubmit_errorStatus(t *testing.T) {
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusBadRequest, `{"message":"bad"}`)
	})
	_, err := svc.Submit(&requestsmodels.IdsecARSSubmitAccessRequest{TargetCategory: requestsmodels.TargetCategoryVM})
	require.ErrorContains(t, err, "failed to submit access request - [400]")
}

func TestListBy_pagesByOffsetUntilTotalCount(t *testing.T) {
	svc, recorded := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("offset") {
		case "":
			respond(w, http.StatusOK, `{"items":[{"requestId":"r1","targetCategory":"VM","requestState":"PENDING","creationTime":"t1"}],"count":1,"totalCount":2}`)
		case "1":
			respond(w, http.StatusOK, `{"items":[{"requestId":"r2","targetCategory":"CLOUD_CONSOLE","requestState":"FINISHED"}],"count":1,"totalCount":2}`)
		default:
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
	})
	pages, err := svc.ListBy(&requestsmodels.IdsecARSFilter{Limit: 1, Filter: "x"})
	require.NoError(t, err)
	var ids []string
	for page := range pages {
		for _, item := range page.Items {
			ids = append(ids, item.RequestID)
		}
	}
	assert.Equal(t, []string{"r1", "r2"}, ids)
	require.Len(t, *recorded, 2)
	assert.Equal(t, map[string]string{"extended": "false", "limit": "1", "filter": "x"}, (*recorded)[0].Query)
	assert.Equal(t, "1", (*recorded)[1].Query["offset"])
}

func TestList_stopsOnShortPage(t *testing.T) {
	svc, recorded := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, `{"items":[{"requestId":"r1","targetCategory":"VM","requestState":"PENDING"}],"count":1,"totalCount":5}`)
	})
	pages, err := svc.List()
	require.NoError(t, err)
	for range pages {
	}
	assert.Len(t, *recorded, 1)
}

func TestList_errorStatus(t *testing.T) {
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusInternalServerError, `{"message":"boom"}`)
	})
	_, err := svc.List()
	require.ErrorContains(t, err, "failed to list access requests")
}

func TestStats(t *testing.T) {
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, `{"items":[
			{"requestId":"r1","targetCategory":"VM","requestState":"PENDING"},
			{"requestId":"r2","targetCategory":"VM","requestState":"FINISHED","requestResult":"APPROVED"},
			{"requestId":"r3","targetCategory":"CLOUD_CONSOLE","requestState":"FINISHED","requestResult":"REJECTED"}
		],"count":3,"totalCount":3}`)
	})
	stats, err := svc.Stats()
	require.NoError(t, err)
	assert.Equal(t, 3, stats.RequestsCount)
	assert.Equal(t, map[string]int{"VM": 2, "CLOUD_CONSOLE": 1}, stats.RequestsCountByCategory)
	assert.Equal(t, map[requestsmodels.IdsecARSAccessRequestState]int{"PENDING": 1, "FINISHED": 2}, stats.RequestsCountByState)
	assert.Equal(t, map[requestsmodels.IdsecARSAccessRequestResult]int{"UNKNOWN": 1, "APPROVED": 1, "REJECTED": 1}, stats.RequestsCountByResult)
}

func TestListRequestForms_sendsFiltersAsCamelCaseQuery(t *testing.T) {
	svc, recorded := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, requestFormsResponse)
	})
	_, err := svc.ListRequestForms(&requestsmodels.IdsecARSListAccessRequestForms{
		TargetCategory: requestsmodels.TargetCategoryCloudConsole,
		RequestType:    requestsmodels.RequestTypeDualControl,
	})
	require.NoError(t, err)
	rec := (*recorded)[0]
	assert.Equal(t, "/api/workflows/request-forms", rec.Path)
	assert.Equal(t, map[string]string{"targetCategory": "CLOUD_CONSOLE", "requestType": "DUAL_CONTROL"}, rec.Query)
}

func TestSubmit_sendsGroupTargetCategory(t *testing.T) {
	svc, recorded := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, accessRequestJSON("req-1", "STARTING", "UNKNOWN"))
	})
	_, err := svc.Submit(&requestsmodels.IdsecARSSubmitAccessRequest{
		TargetCategory: requestsmodels.TargetCategoryGroup,
		RequestDetails: map[string]interface{}{"reason": "test"},
	})
	require.NoError(t, err)
	assert.Equal(t, "GROUP", (*recorded)[0].Body["target_category"])
}

func TestListRequestForms_sendsGroupTargetCategory(t *testing.T) {
	svc, recorded := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, `{"requestForms":[]}`)
	})
	_, err := svc.ListRequestForms(&requestsmodels.IdsecARSListAccessRequestForms{TargetCategory: requestsmodels.TargetCategoryGroup})
	require.NoError(t, err)
	assert.Equal(t, "GROUP", (*recorded)[0].Query["targetCategory"])
}

func TestListRequestForms_defaultsToOnDemand(t *testing.T) {
	svc, recorded := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, requestFormsResponse)
	})
	_, err := svc.ListRequestForms(&requestsmodels.IdsecARSListAccessRequestForms{TargetCategory: requestsmodels.TargetCategoryVM})
	require.NoError(t, err)
	assert.Equal(t, "ON_DEMAND", (*recorded)[0].Query["requestType"])
}

func TestListRequestForms_parsesResponse(t *testing.T) {
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, requestFormsResponse)
	})
	forms, err := svc.ListRequestForms(&requestsmodels.IdsecARSListAccessRequestForms{TargetCategory: requestsmodels.TargetCategoryCloudConsole})
	require.NoError(t, err)
	require.Len(t, forms.RequestForms, 1)
	form := forms.RequestForms[0]
	assert.Equal(t, requestsmodels.TargetCategoryCloudConsole, form.TargetCategory)
	assert.Equal(t, requestsmodels.RequestTypeOnDemand, form.RequestType)
	questions := form.RequestForm.Questions
	require.Len(t, questions, 3)
	assert.Equal(t, "location_type", questions[0].Key)
	assert.Equal(t, true, questions[0].Required)
	assert.Equal(t, requestsmodels.QueryValueTypeChoice, questions[0].ValueType)
	assert.Equal(t, []interface{}{"AWS", "GCP", "Azure"}, questions[0].ValueChoices)
	conditional, ok := questions[1].Required.(map[string]interface{})
	require.True(t, ok, "conditional required must decode as an object")
	assert.Equal(t, "OR", conditional["operator"])
	assert.Equal(t, "type_checker_validator", questions[1].Validators[0].Name)
	assert.Equal(t, "Medium", questions[2].Default)
}

func TestListRequestForms_emptyResponse(t *testing.T) {
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, `{"requestForms":[]}`)
	})
	forms, err := svc.ListRequestForms(&requestsmodels.IdsecARSListAccessRequestForms{TargetCategory: requestsmodels.TargetCategoryVM})
	require.NoError(t, err)
	assert.Empty(t, forms.RequestForms)
	assert.NotNil(t, forms.RequestForms)
}

func TestListRequestForms_errorStatus(t *testing.T) {
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusUnprocessableEntity, `{"message":"The specified category type input is invalid"}`)
	})
	_, err := svc.ListRequestForms(&requestsmodels.IdsecARSListAccessRequestForms{TargetCategory: requestsmodels.TargetCategoryVM})
	require.ErrorContains(t, err, "failed to list access request forms - [422]")
}

func TestSubmit_pollTimesOut(t *testing.T) {
	pollInterval = time.Millisecond
	pollTimeout = 20 * time.Millisecond
	t.Cleanup(func() { pollTimeout = time.Hour })
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, accessRequestJSON("req-1", "RUNNING", "UNKNOWN"))
	})
	_, err := svc.Submit(&requestsmodels.IdsecARSSubmitAccessRequest{Poll: true, TargetCategory: requestsmodels.TargetCategoryVM})
	require.ErrorContains(t, err, "timed out polling access request [req-1]")
}
