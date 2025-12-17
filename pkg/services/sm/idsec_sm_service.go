package sm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	smmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sm/models"
)

const (
	sessionsURL          = "/api/sessions"
	sessionURL           = "/api/sessions/%s"
	sessionActivitiesURL = "/api/sessions/%s/activities"
)

// IdsecSMPage represents a page of IdsecSMSession items.
type IdsecSMPage = common.IdsecPage[smmodels.IdsecSMSession]

// IdsecSMActivitiesPage represents a page of IdsecSMSessionActivity items.
type IdsecSMActivitiesPage = common.IdsecPage[smmodels.IdsecSMSessionActivity]

// IdsecSMService is the implementation of the IdsecSMService interface.
type IdsecSMService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
}

// NewIdsecSMService creates a new instance of IdsecSMService.
func NewIdsecSMService(authenticators ...auth.IdsecAuth) (*IdsecSMService, error) {
	SMService := &IdsecSMService{}
	var SMServiceInterface services.IdsecService = SMService
	baseService, err := services.NewIdsecBaseService(SMServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "sessionmonitoring", ".", "", SMService.refreshSMAuth)
	if err != nil {
		return nil, err
	}
	SMService.client = client
	SMService.ispAuth = ispAuth
	SMService.IdsecBaseService = baseService
	return SMService, nil
}

func (s *IdsecSMService) refreshSMAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

// searchParamsFromFilter private function converts an IdsecSMSessionsFilter to a map of search parameters
func (s *IdsecSMService) searchParamsFromFilter(sessionsFilter *smmodels.IdsecSMSessionsFilter) map[string]string {
	return map[string]string{
		"search": sessionsFilter.Search,
	}
}

// callListSessions private function that retrieves a list of sessions, parameters can be passed to filter the results.
func (s *IdsecSMService) callListSessions(params map[string]string) (*smmodels.IdsecSMSessions, error) {
	if params == nil {
		params = make(map[string]string)
	}
	response, err := s.client.Get(context.Background(), sessionsURL, params)
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
	var sessions smmodels.IdsecSMSessions
	err = mapstructure.Decode(sessionsJSON, &sessions)
	if err != nil {
		return nil, err
	}
	return &sessions, nil
}

// callListSessionActivities private function that retrieves a list of activities for a session, parameters can be passed to filter the results.
func (s *IdsecSMService) callListSessionActivities(sessionID string, params map[string]string) (*smmodels.IdsecSMSessionActivities, error) {
	if params == nil {
		params = make(map[string]string)
	}
	response, err := s.client.Get(context.Background(), fmt.Sprintf(sessionActivitiesURL, sessionID), params)
	if err != nil {
		s.Logger.Error("failed to list session activities: %v", err)
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list session activities - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	sessionActivitiesJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var sessionActivities smmodels.IdsecSMSessionActivities
	err = mapstructure.Decode(sessionActivitiesJSON, &sessionActivities)
	if err != nil {
		return nil, err
	}
	return &sessionActivities, nil
}

// listPagedSessions private function that retrieves a list of sessions, parameters can be passed to filter the results.
func (s *IdsecSMService) listPagedSessions(params map[string]string) (<-chan *IdsecSMPage, error) {
	results := make(chan *IdsecSMPage)
	if params == nil {
		params = make(map[string]string)
	}
	offset := 0
	go func() {
		defer close(results)
		for {
			sessionsResponse, err := s.callListSessions(params)
			if err != nil {
				s.Logger.Error("failed to list sessions: %v", err)
				return
			}
			if sessionsResponse.ReturnedCount == 0 {
				break
			}
			sessions := make([]*smmodels.IdsecSMSession, len(sessionsResponse.Sessions))
			for i := range sessionsResponse.Sessions {
				sessions[i] = &sessionsResponse.Sessions[i]
			}
			results <- &IdsecSMPage{Items: sessions}
			offset += sessionsResponse.ReturnedCount
			params["offset"] = strconv.Itoa(offset)
		}
	}()
	return results, nil
}

// listActivities private function that retrieves the activities by session ID
// parameters can be passed to filter the results.
func (s *IdsecSMService) listPagedSessionActivities(sessionID string) (<-chan *IdsecSMActivitiesPage, error) {
	results := make(chan *IdsecSMActivitiesPage)
	params := make(map[string]string)
	offset := 0
	go func() {
		defer close(results)
		for {
			sessionActivitiesResponse, err := s.callListSessionActivities(sessionID, params)
			if err != nil {
				s.Logger.Error("failed to list session activities: %v", err)
				return
			}
			if sessionActivitiesResponse.ReturnedCount == 0 {
				break
			}
			activities := make([]*smmodels.IdsecSMSessionActivity, len(sessionActivitiesResponse.Activities))
			for i := range sessionActivitiesResponse.Activities {
				activities[i] = &sessionActivitiesResponse.Activities[i]
			}
			results <- &IdsecSMActivitiesPage{Items: activities}
			offset += sessionActivitiesResponse.ReturnedCount
			params["offset"] = strconv.Itoa(offset)

		}
	}()
	return results, nil
}

// ListSessions retrieves a list of sessions
func (s *IdsecSMService) ListSessions() (<-chan *IdsecSMPage, error) {
	return s.listPagedSessions(nil)
}

// CountSessions retrieves the count of sessions on the last 24 hours
func (s *IdsecSMService) CountSessions() (int, error) {
	sessions, err := s.callListSessions(nil)
	if err != nil {
		s.Logger.Error("failed to count sessions: %v", err)
		return 0, err
	}
	return sessions.ReturnedCount, err
}

// ListSessionsBy retrieves a list of sessions and applies an optional filter.
func (s *IdsecSMService) ListSessionsBy(filter *smmodels.IdsecSMSessionsFilter) (<-chan *IdsecSMPage, error) {
	return s.listPagedSessions(s.searchParamsFromFilter(filter))
}

// CountSessionsBy retrieves the count of sessions on the last 24 hours and applies an optional filter.
func (s *IdsecSMService) CountSessionsBy(filter *smmodels.IdsecSMSessionsFilter) (int, error) {
	sessions, err := s.callListSessions(s.searchParamsFromFilter(filter))
	if err != nil {
		s.Logger.Error("failed to count sessions: %v", err)
		return 0, err
	}
	return sessions.FilteredCount, err
}

// ListSessionActivities retrieves the activities of a session by its ID
func (s *IdsecSMService) ListSessionActivities(sessionActivities *smmodels.IdsecSIASMGetSessionActivities) (<-chan *IdsecSMActivitiesPage, error) {
	return s.listPagedSessionActivities(sessionActivities.SessionID)
}

// CountSessionActivities retrieves the count all session activities by session id
func (s *IdsecSMService) CountSessionActivities(activities *smmodels.IdsecSIASMGetSessionActivities) (int, error) {
	sessionActivities, err := s.callListSessionActivities(activities.SessionID, nil)
	if err != nil {
		s.Logger.Error("failed counting session activities: %v", err)
		return 0, err
	}
	return sessionActivities.ReturnedCount, err
}

// ListSessionActivitiesBy retrieves the activities of a session by its ID and applies an optional filter.
func (s *IdsecSMService) ListSessionActivitiesBy(filter *smmodels.IdsecSMSessionActivitiesFilter) (<-chan *IdsecSMActivitiesPage, error) {
	pagedSessionActivities, err := s.listPagedSessionActivities(filter.SessionID)
	if err != nil {
		s.Logger.Error("failed to list session activities: %v", err)
		return nil, err
	}
	out := make(chan *IdsecSMActivitiesPage)

	go func() {
		defer close(out)

		for page := range pagedSessionActivities {
			filteredItems := make([]*smmodels.IdsecSMSessionActivity, 0, len(page.Items))

			for _, activity := range page.Items {
				if filter.CommandContains == "" || strings.Contains(activity.Command, filter.CommandContains) {
					filteredItems = append(filteredItems, activity)
				}
			}

			out <- &IdsecSMActivitiesPage{
				Items: filteredItems,
			}
		}
	}()

	return out, nil
}

// CountSessionActivitiesBy retrieves the count all session activities by session id and applies an optional filter.
func (s *IdsecSMService) CountSessionActivitiesBy(filter *smmodels.IdsecSMSessionActivitiesFilter) (int, error) {
	pagedSessionActivities, err := s.ListSessionActivitiesBy(filter)
	if err != nil {
		s.Logger.Error("failed counting session activities: %v", err)
		return 0, err
	}
	count := 0
	for page := range pagedSessionActivities {
		count += len(page.Items)
	}
	return count, err
}

// SessionsStats retrieves the session statistics for the SM service.
func (s *IdsecSMService) SessionsStats() (*smmodels.IdsecSMSessionsStats, error) {
	s.Logger.Info("Calculating sessions stats for the last 30 days")
	startTimeFrom := time.Now().AddDate(0, 0, -30).UTC().Format("2006-01-02T15:04:05Z")

	filter := smmodels.IdsecSMSessionsFilter{
		Search: fmt.Sprintf("startTime ge %s", startTimeFrom),
	}
	pages, err := s.ListSessionsBy(&filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}

	var sessions []*smmodels.IdsecSMSession
	for page := range pages {
		sessions = append(sessions, page.Items...)
	}

	stats := &smmodels.IdsecSMSessionsStats{}
	stats.SessionsCount = len(sessions)
	stats.SessionsFailureCount = 0
	stats.SessionsCountPerApplicationCode = make(map[string]int)
	stats.SessionsCountPerPlatform = make(map[string]int)
	stats.SessionsCountPerProtocol = make(map[string]int)
	stats.SessionsCountPerStatus = make(map[smmodels.IdsecSMSessionStatus]int)

	for _, session := range sessions {
		if session.SessionStatus == smmodels.Failed {
			stats.SessionsFailureCount++
		}
		stats.SessionsCountPerApplicationCode[session.ApplicationCode]++
		stats.SessionsCountPerPlatform[session.Platform]++
		stats.SessionsCountPerProtocol[session.Protocol]++
		stats.SessionsCountPerStatus[session.SessionStatus]++
	}

	return stats, nil
}

// Session retrieves a session by its ID
func (s *IdsecSMService) Session(getSession *smmodels.IdsecSIASMGetSession) (*smmodels.IdsecSMSession, error) {
	s.Logger.Info("Getting session [%s]", getSession.SessionID)
	response, err := s.client.Get(context.Background(), fmt.Sprintf(sessionURL, getSession.SessionID), nil)
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
	var session smmodels.IdsecSMSession
	err = mapstructure.Decode(sessionJSON, &session)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// ServiceConfig returns the service configuration for the IdsecSMservice.
func (s *IdsecSMService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
