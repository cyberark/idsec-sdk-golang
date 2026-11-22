package requests

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/pagination"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	requestsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/ars/requests/models"
)

const (
	accessRequestsURL        = "/api/workflows/requests"
	accessRequestURL         = "/api/workflows/requests/%s"
	cancelAccessRequestURL   = "/api/workflows/requests/%s/cancel"
	finalizeAccessRequestURL = "/api/workflows/requests/%s/finalize"
	requestFormsURL          = "/api/workflows/request-forms"

	defaultListLimit  = 1000
	maxListIterations = 100
)

// pollInterval is the sleep between status checks while polling, and pollTimeout bounds the whole poll;
// variables so tests can shorten them.
var (
	pollInterval = time.Second
	pollTimeout  = time.Hour
)

// IdsecARSAccessRequestsPage represents a page of IdsecARSAccessRequest items.
type IdsecARSAccessRequestsPage = common.IdsecPage[requestsmodels.IdsecARSAccessRequest]

// pollStatus is the coarse status of an access request, used to decide when polling is done.
type pollStatus int

const (
	pollStatusInProgress pollStatus = iota
	pollStatusPending
	pollStatusSuccess
	pollStatusFailed
)

// IdsecARSRequestsService is the implementation of the ARS access requests service.
type IdsecARSRequestsService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecARSRequestsService creates a new instance of IdsecARSRequestsService.
func NewIdsecARSRequestsService(authenticators ...auth.IdsecAuth) (*IdsecARSRequestsService, error) {
	requestsService := &IdsecARSRequestsService{}
	var requestsServiceInterface services.IdsecService = requestsService
	baseService, err := services.NewIdsecBaseService(requestsServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, arsServiceName(commonmodels.GetDeployEnv()), ".", "", requestsService.refreshARSAuth)
	if err != nil {
		return nil, err
	}

	requestsService.IdsecBaseService = baseService
	requestsService.IdsecISPBaseService = ispBaseService
	return requestsService, nil
}

// arsServiceName returns the ARS host prefix, which is "uar" in production and "ars" elsewhere.
func arsServiceName(env commonmodels.AwsEnv) string {
	if env == commonmodels.Prod {
		return "uar"
	}
	return "ars"
}

func (s *IdsecARSRequestsService) refreshARSAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ISPAuth())
}

func closeBody(body io.ReadCloser) {
	if err := body.Close(); err != nil {
		common.GlobalLogger.Warning("Error closing response body")
	}
}

// decodeAccessRequest validates the response status and decodes an access request from it.
func decodeAccessRequest(response *http.Response, operation string) (*requestsmodels.IdsecARSAccessRequest, error) {
	defer closeBody(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to %s - [%d] - [%s]", operation, response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	requestJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s response: %w", operation, err)
	}
	requestMap, ok := requestJSON.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to parse %s response: unexpected type %T", operation, requestJSON)
	}
	return decodeAccessRequestMap(requestMap)
}

// decodeAccessRequestMap decodes a single access request, falling back to the deprecated
// request_survey_input field when request_details is absent.
func decodeAccessRequestMap(requestMap map[string]interface{}) (*requestsmodels.IdsecARSAccessRequest, error) {
	if _, ok := requestMap["request_details"]; !ok {
		if surveyInput, ok := requestMap["request_survey_input"]; ok {
			requestMap["request_details"] = surveyInput
		}
	}
	var request requestsmodels.IdsecARSAccessRequest
	if err := mapstructure.Decode(requestMap, &request); err != nil {
		return nil, fmt.Errorf("failed to decode access request: %w", err)
	}
	if request.RequestResult == "" {
		request.RequestResult = requestsmodels.RequestResultUnknown
	}
	return &request, nil
}

// listQueryFromFilter converts a requests filter to list query parameters.
func listQueryFromFilter(filter *requestsmodels.IdsecARSFilter) map[string]string {
	if filter == nil {
		filter = &requestsmodels.IdsecARSFilter{}
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = defaultListLimit
	}
	query := map[string]string{
		"extended": strconv.FormatBool(filter.Extended),
		"limit":    strconv.Itoa(limit),
	}
	if filter.Offset > 0 {
		query["offset"] = strconv.Itoa(filter.Offset)
	}
	if sort := sortQueryParam(filter.Sort); sort != "" {
		query["sort"] = sort
	}
	if filter.Filter != "" {
		query["filter"] = filter.Filter
	}
	return query
}

// sortQueryParam joins sort clauses into "field [direction],..." skipping clauses without a field.
func sortQueryParam(sort []requestsmodels.IdsecARSSortQuery) string {
	clauses := make([]string, 0, len(sort))
	for _, item := range sort {
		if item.Field == "" {
			continue
		}
		if item.Direction != "" {
			clauses = append(clauses, fmt.Sprintf("%s %s", item.Field, item.Direction))
		} else {
			clauses = append(clauses, item.Field)
		}
	}
	return strings.Join(clauses, ",")
}

func intFromResultMap(resultMap map[string]interface{}, key string) int {
	switch v := resultMap[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	default:
		return 0
	}
}

func decodeAccessRequestsFromResultMap(resultMap map[string]interface{}) ([]*requestsmodels.IdsecARSAccessRequest, error) {
	items, err := pagination.ExtractItemsFromResult(resultMap, "access requests", "items")
	if err != nil {
		return nil, err
	}
	requests := make([]*requestsmodels.IdsecARSAccessRequest, 0, len(items))
	for _, item := range items {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to decode access requests: unexpected item type %T", item)
		}
		request, err := decodeAccessRequestMap(itemMap)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	return requests, nil
}

// listAccessRequests pages through the access requests list, advancing the offset by the returned count
// until all items are read, a short page is returned, or the iteration cap is reached.
func (s *IdsecARSRequestsService) listAccessRequests(filter *requestsmodels.IdsecARSFilter) (<-chan *IdsecARSAccessRequestsPage, error) {
	initialQuery := listQueryFromFilter(filter)
	limit, _ := strconv.Atoi(initialQuery["limit"])
	readCount := 0
	iteration := 1
	return pagination.ListAllPaginated(
		context.Background(),
		pagination.HTTPGetFetch(s.ISPClient(), accessRequestsURL, initialQuery),
		pagination.ListPaginatedConfig[requestsmodels.IdsecARSAccessRequest]{
			ResourceName: "access requests",
			Decode:       decodeAccessRequestsFromResultMap,
			NextQuery: func(resultMap map[string]interface{}, current map[string]string) (map[string]string, bool) {
				count := intFromResultMap(resultMap, "count")
				readCount += count
				if iteration >= maxListIterations || count < limit || readCount >= intFromResultMap(resultMap, "total_count") {
					return nil, false
				}
				iteration++
				offset, _ := strconv.Atoi(current["offset"])
				next := maps.Clone(current)
				next["offset"] = strconv.Itoa(offset + count)
				return next, true
			},
		},
	)
}

// taskStatus maps an access request state and result to a coarse polling status.
func taskStatus(request *requestsmodels.IdsecARSAccessRequest) pollStatus {
	switch request.RequestState {
	case requestsmodels.RequestStateFinished:
		switch request.RequestResult {
		case requestsmodels.RequestResultApproved, requestsmodels.RequestResultRejected, requestsmodels.RequestResultCanceled:
			return pollStatusSuccess
		}
		return pollStatusFailed
	case requestsmodels.RequestStatePending:
		return pollStatusPending
	case requestsmodels.RequestStateStarting, requestsmodels.RequestStateRunning:
		return pollStatusInProgress
	}
	return pollStatusFailed
}

// pollAccessRequest polls the access request until it reaches one of the target statuses, fails, or times out.
func (s *IdsecARSRequestsService) pollAccessRequest(
	request *requestsmodels.IdsecARSAccessRequest,
	targetStatuses []pollStatus,
) (*requestsmodels.IdsecARSAccessRequest, error) {
	deadline := time.Now().Add(pollTimeout)
	for {
		status := taskStatus(request)
		if slices.Contains(targetStatuses, status) {
			return request, nil
		}
		if status == pollStatusFailed {
			return request, fmt.Errorf("access request [%s] failed - state [%s] result [%s]", request.RequestID, request.RequestState, request.RequestResult)
		}
		if time.Now().After(deadline) {
			return request, fmt.Errorf("timed out polling access request [%s] - last state [%s]", request.RequestID, request.RequestState)
		}
		time.Sleep(pollInterval)
		s.Logger.Debug("Polling access request [%s], current state [%s]", request.RequestID, request.RequestState)
		updated, err := s.Get(&requestsmodels.IdsecARSGetAccessRequest{RequestID: request.RequestID})
		if err != nil {
			return request, err
		}
		request = updated
	}
}

// targetStatuses returns the statuses at which polling stops for an action.
func targetStatuses(waitUntilFinished bool, pendingIsFinal bool) []pollStatus {
	if waitUntilFinished {
		return []pollStatus{pollStatusSuccess}
	}
	if pendingIsFinal {
		return []pollStatus{pollStatusPending, pollStatusSuccess}
	}
	return []pollStatus{pollStatusPending}
}

// Submit submits a new access request.
// When Poll is set, waits until the request is pending (or finished, if WaitUntilFinished is set).
func (s *IdsecARSRequestsService) Submit(submitRequest *requestsmodels.IdsecARSSubmitAccessRequest) (*requestsmodels.IdsecARSAccessRequest, error) {
	s.Logger.Info("Submitting an access request [%s]", submitRequest.TargetCategory)
	requestType := submitRequest.RequestType
	if requestType == "" {
		requestType = requestsmodels.RequestTypeOnDemand
	}
	body := map[string]interface{}{
		"target_category":     submitRequest.TargetCategory,
		"request_type":        requestType,
		"request_details":     submitRequest.RequestDetails,
		"association":         nil,
		"wait_until_finished": submitRequest.WaitUntilFinished,
	}
	if associationID, ok := submitRequest.Association["association_id"]; ok && associationID != nil && associationID != "" {
		body["association"] = submitRequest.Association
	}
	response, err := s.ISPClient().Post(context.Background(), accessRequestsURL, body)
	if err != nil {
		return nil, err
	}
	request, err := decodeAccessRequest(response, "submit access request")
	if err != nil {
		return nil, err
	}
	if submitRequest.Poll {
		return s.pollAccessRequest(request, targetStatuses(submitRequest.WaitUntilFinished, false))
	}
	return request, nil
}

// Cancel cancels an access request.
// When Poll is set, waits until the cancellation finishes.
func (s *IdsecARSRequestsService) Cancel(cancelRequest *requestsmodels.IdsecARSCancelAccessRequest) (*requestsmodels.IdsecARSAccessRequest, error) {
	s.Logger.Info("Canceling an access request [%s]", cancelRequest.RequestID)
	body := map[string]interface{}{
		"cancel_reason": cancelRequest.CancelReason,
	}
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(cancelAccessRequestURL, cancelRequest.RequestID), body)
	if err != nil {
		return nil, err
	}
	request, err := decodeAccessRequest(response, "cancel access request")
	if err != nil {
		return nil, err
	}
	if cancelRequest.Poll {
		return s.pollAccessRequest(request, targetStatuses(true, false))
	}
	return request, nil
}

// Finalize finalizes (approves / rejects) an access request.
// When Poll is set, waits until the request is pending or finished (or only finished, if WaitUntilFinished is set).
func (s *IdsecARSRequestsService) Finalize(finalizeRequest *requestsmodels.IdsecARSFinalizeAccessRequest) (*requestsmodels.IdsecARSAccessRequest, error) {
	s.Logger.Info("Finalizing an access request [%s]", finalizeRequest.RequestID)
	body := map[string]interface{}{
		"result":              finalizeRequest.Result,
		"request_details":     finalizeRequest.RequestDetails,
		"finalization_reason": nil,
		"wait_until_finished": finalizeRequest.WaitUntilFinished,
	}
	if finalizeRequest.FinalizationReason != "" {
		body["finalization_reason"] = finalizeRequest.FinalizationReason
	}
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(finalizeAccessRequestURL, finalizeRequest.RequestID), body)
	if err != nil {
		return nil, err
	}
	request, err := decodeAccessRequest(response, "finalize access request")
	if err != nil {
		return nil, err
	}
	if finalizeRequest.Poll {
		return s.pollAccessRequest(request, targetStatuses(finalizeRequest.WaitUntilFinished, true))
	}
	return request, nil
}

// List lists all access requests.
func (s *IdsecARSRequestsService) List() (<-chan *IdsecARSAccessRequestsPage, error) {
	s.Logger.Info("Listing all access requests")
	return s.listAccessRequests(nil)
}

// ListBy lists access requests matching the given filter.
func (s *IdsecARSRequestsService) ListBy(filter *requestsmodels.IdsecARSFilter) (<-chan *IdsecARSAccessRequestsPage, error) {
	s.Logger.Info("Listing access requests with filters [%+v]", filter)
	return s.listAccessRequests(filter)
}

// Get retrieves an access request by its ID.
func (s *IdsecARSRequestsService) Get(getRequest *requestsmodels.IdsecARSGetAccessRequest) (*requestsmodels.IdsecARSAccessRequest, error) {
	s.Logger.Info("Getting an access request [%s]", getRequest.RequestID)
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(accessRequestURL, getRequest.RequestID), nil)
	if err != nil {
		return nil, err
	}
	return decodeAccessRequest(response, "get access request")
}

// Stats calculates access requests statistics.
func (s *IdsecARSRequestsService) Stats() (*requestsmodels.IdsecARSAccessRequestsStats, error) {
	s.Logger.Info("Calculating access requests stats")
	pages, err := s.List()
	if err != nil {
		return nil, err
	}
	stats := &requestsmodels.IdsecARSAccessRequestsStats{
		RequestsCountByCategory: map[string]int{},
		RequestsCountByState:    map[requestsmodels.IdsecARSAccessRequestState]int{},
		RequestsCountByResult:   map[requestsmodels.IdsecARSAccessRequestResult]int{},
	}
	for page := range pages {
		for _, request := range page.Items {
			stats.RequestsCount++
			if request.TargetCategory != "" {
				stats.RequestsCountByCategory[request.TargetCategory]++
			}
			if request.RequestState != "" {
				stats.RequestsCountByState[request.RequestState]++
			}
			if request.RequestResult != "" {
				stats.RequestsCountByResult[request.RequestResult]++
			}
		}
	}
	return stats, nil
}

// ListRequestForms lists the access request form structures for a target category and request type.
// The structure describes the questions to answer, their value types and validations, when submitting an access request.
func (s *IdsecARSRequestsService) ListRequestForms(listRequestForms *requestsmodels.IdsecARSListAccessRequestForms) (*requestsmodels.IdsecARSAccessRequestForms, error) {
	requestType := listRequestForms.RequestType
	if requestType == "" {
		requestType = requestsmodels.RequestTypeOnDemand
	}
	s.Logger.Info("Listing access request forms for target category [%s] and request type [%s]", listRequestForms.TargetCategory, requestType)
	query := map[string]string{
		"targetCategory": string(listRequestForms.TargetCategory),
		"requestType":    string(requestType),
	}
	response, err := s.ISPClient().Get(context.Background(), requestFormsURL, query)
	if err != nil {
		return nil, err
	}
	defer closeBody(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list access request forms - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	formsJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse access request forms response: %w", err)
	}
	var forms requestsmodels.IdsecARSAccessRequestForms
	if err := mapstructure.Decode(formsJSON, &forms); err != nil {
		return nil, fmt.Errorf("failed to parse access request forms response: %w", err)
	}
	if forms.RequestForms == nil {
		forms.RequestForms = []requestsmodels.IdsecARSAccessRequestForm{}
	}
	return &forms, nil
}

// ServiceConfig returns the service configuration for the IdsecARSRequestsService.
func (s *IdsecARSRequestsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
