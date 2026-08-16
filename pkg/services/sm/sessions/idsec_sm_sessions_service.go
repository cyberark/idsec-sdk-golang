package sessions

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/pagination"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	sessionsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sm/sessions/models"
)

const (
	sessionsURL = "/api/sessions"
	sessionURL  = "/api/sessions/%s"
)

// IdsecSMSessionsPage represents a page of IdsecSMSession items.
type IdsecSMSessionsPage = common.IdsecPage[sessionsmodels.IdsecSMSession]

// IdsecSMSessionsService is the implementation of the SM Sessions service.
type IdsecSMSessionsService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecSMSessionsService creates a new instance of IdsecSMSessionsService.
func NewIdsecSMSessionsService(authenticators ...auth.IdsecAuth) (*IdsecSMSessionsService, error) {
	sessionsService := &IdsecSMSessionsService{}
	var sessionsServiceInterface services.IdsecService = sessionsService
	baseService, err := services.NewIdsecBaseService(sessionsServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "sessionmonitoring", ".", "", sessionsService.refreshSMAuth)
	if err != nil {
		return nil, err
	}

	sessionsService.IdsecBaseService = baseService
	sessionsService.IdsecISPBaseService = ispBaseService
	return sessionsService, nil
}

func (s *IdsecSMSessionsService) refreshSMAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

// searchParamsFromFilter converts an IdsecSMSessionsFilter to a map of search parameters
func (s *IdsecSMSessionsService) searchParamsFromFilter(sessionsFilter *sessionsmodels.IdsecSMSessionsFilter) map[string]string {
	return map[string]string{
		"search": sessionsFilter.Search,
	}
}

// callListSessions retrieves a list of sessions, parameters can be passed to filter the results.
func (s *IdsecSMSessionsService) callListSessions(params map[string]string) (*sessionsmodels.IdsecSMSessions, error) {
	if params == nil {
		params = make(map[string]string)
	}
	response, err := s.ISPClient().Get(context.Background(), sessionsURL, params)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list sessions - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	sessionsJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var sessions sessionsmodels.IdsecSMSessions
	err = mapstructure.Decode(sessionsJSON, &sessions)
	if err != nil {
		return nil, err
	}
	return &sessions, nil
}

// returnedCountFromResultMap reads the "returned_count" field the SM list endpoints use to
// report how many items were returned on the current page (0 signals the last page).
func returnedCountFromResultMap(resultMap map[string]interface{}) (int, bool) {
	switch v := resultMap["returned_count"].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	default:
		return 0, false
	}
}

// nextOffsetQuery builds the next page's query by advancing the "offset" param in current by
// returnedCount, preserving every other filter/search param already present.
func nextOffsetQuery(current map[string]string, returnedCount int) map[string]string {
	offset := 0
	if v, ok := current["offset"]; ok {
		offset, _ = strconv.Atoi(v)
	}
	next := make(map[string]string, len(current)+1)
	for k, v := range current {
		next[k] = v
	}
	next["offset"] = strconv.Itoa(offset + returnedCount)
	return next
}

func decodeSessionsFromResultMap(resultMap map[string]interface{}) ([]*sessionsmodels.IdsecSMSession, error) {
	items, err := pagination.ExtractItemsFromResult(resultMap, "sessions", "sessions")
	if err != nil {
		return nil, err
	}
	var sessions []*sessionsmodels.IdsecSMSession
	if err := mapstructure.Decode(items, &sessions); err != nil {
		return nil, fmt.Errorf("failed to decode sessions: %w", err)
	}
	return sessions, nil
}

// listPagedSessions retrieves a list of sessions, parameters can be passed to filter the results.
func (s *IdsecSMSessionsService) listPagedSessions(params map[string]string) (<-chan *IdsecSMSessionsPage, error) {
	if params == nil {
		params = make(map[string]string)
	}
	return pagination.ListAllPaginated[sessionsmodels.IdsecSMSession](
		context.Background(),
		pagination.HTTPGetFetch(s.ISPClient(), sessionsURL, params),
		pagination.ListPaginatedConfig[sessionsmodels.IdsecSMSession]{
			ResourceName: "sessions",
			Decode:       decodeSessionsFromResultMap,
			NextQuery: func(resultMap map[string]interface{}, current map[string]string) (map[string]string, bool) {
				returnedCount, ok := returnedCountFromResultMap(resultMap)
				if !ok || returnedCount == 0 {
					return nil, false
				}
				return nextOffsetQuery(current, returnedCount), true
			},
		},
	)
}

// List retrieves a list of sessions.
func (s *IdsecSMSessionsService) List() (<-chan *IdsecSMSessionsPage, error) {
	return s.listPagedSessions(nil)
}

// Count retrieves the count of sessions on the last 24 hours.
func (s *IdsecSMSessionsService) Count() (int, error) {
	sessions, err := s.callListSessions(nil)
	if err != nil {
		s.Logger.Error("failed to count sessions: %v", err)
		return 0, err
	}
	return sessions.ReturnedCount, err
}

// ListBy retrieves a list of sessions and applies an optional filter.
func (s *IdsecSMSessionsService) ListBy(filter *sessionsmodels.IdsecSMSessionsFilter) (<-chan *IdsecSMSessionsPage, error) {
	return s.listPagedSessions(s.searchParamsFromFilter(filter))
}

// CountBy retrieves the count of sessions on the last 24 hours and applies an optional filter.
func (s *IdsecSMSessionsService) CountBy(filter *sessionsmodels.IdsecSMSessionsFilter) (int, error) {
	sessions, err := s.callListSessions(s.searchParamsFromFilter(filter))
	if err != nil {
		s.Logger.Error("failed to count sessions: %v", err)
		return 0, err
	}
	return sessions.FilteredCount, err
}

// Get retrieves a session by its ID.
func (s *IdsecSMSessionsService) Get(getSession *sessionsmodels.IdsecSIASMGetSession) (*sessionsmodels.IdsecSMSession, error) {
	s.Logger.Info("Getting session [%s]", getSession.SessionID)
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(sessionURL, getSession.SessionID), nil)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get session - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	sessionJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var session sessionsmodels.IdsecSMSession
	err = mapstructure.Decode(sessionJSON, &session)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// Stats retrieves the session statistics for the SM service.
func (s *IdsecSMSessionsService) Stats() (*sessionsmodels.IdsecSMSessionsStats, error) {
	s.Logger.Info("Calculating sessions stats for the last 30 days")
	startTimeFrom := time.Now().AddDate(0, 0, -30).UTC().Format("2006-01-02T15:04:05Z")

	filter := sessionsmodels.IdsecSMSessionsFilter{
		Search: fmt.Sprintf("startTime ge %s", startTimeFrom),
	}
	pages, err := s.ListBy(&filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}

	var sessions []*sessionsmodels.IdsecSMSession
	for page := range pages {
		sessions = append(sessions, page.Items...)
	}

	stats := &sessionsmodels.IdsecSMSessionsStats{}
	stats.SessionsCount = len(sessions)
	stats.SessionsFailureCount = 0
	stats.SessionsCountPerApplicationCode = make(map[string]int)
	stats.SessionsCountPerPlatform = make(map[string]int)
	stats.SessionsCountPerProtocol = make(map[string]int)
	stats.SessionsCountPerStatus = make(map[sessionsmodels.IdsecSMSessionStatus]int)

	for _, session := range sessions {
		if session.SessionStatus == sessionsmodels.Failed {
			stats.SessionsFailureCount++
		}
		stats.SessionsCountPerApplicationCode[session.ApplicationCode]++
		stats.SessionsCountPerPlatform[session.Platform]++
		stats.SessionsCountPerProtocol[session.Protocol]++
		stats.SessionsCountPerStatus[session.SessionStatus]++
	}

	return stats, nil
}

// ServiceConfig returns the service configuration for the IdsecSMSessionsService.
func (s *IdsecSMSessionsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
