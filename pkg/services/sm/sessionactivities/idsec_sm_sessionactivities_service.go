package sessionactivities

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/pagination"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	sessionactivitiesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sm/sessionactivities/models"
)

const (
	sessionActivitiesURL = "/api/sessions/%s/activities"
)

// IdsecSMSessionActivitiesPage represents a page of IdsecSMSessionActivity items.
type IdsecSMSessionActivitiesPage = common.IdsecPage[sessionactivitiesmodels.IdsecSMSessionActivity]

// IdsecSMSessionActivitiesService is the implementation of the SM Session Activities service.
type IdsecSMSessionActivitiesService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecSMSessionActivitiesService creates a new instance of IdsecSMSessionActivitiesService.
func NewIdsecSMSessionActivitiesService(authenticators ...auth.IdsecAuth) (*IdsecSMSessionActivitiesService, error) {
	activitiesService := &IdsecSMSessionActivitiesService{}
	var activitiesServiceInterface services.IdsecService = activitiesService
	baseService, err := services.NewIdsecBaseService(activitiesServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "sessionmonitoring", ".", "", activitiesService.refreshSMAuth)
	if err != nil {
		return nil, err
	}

	activitiesService.IdsecBaseService = baseService
	activitiesService.IdsecISPBaseService = ispBaseService
	return activitiesService, nil
}

func (s *IdsecSMSessionActivitiesService) refreshSMAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

// callListSessionActivities retrieves a list of activities for a session, parameters can be passed to filter the results.
func (s *IdsecSMSessionActivitiesService) callListSessionActivities(sessionID string, params map[string]string) (*sessionactivitiesmodels.IdsecSMSessionActivities, error) {
	if params == nil {
		params = make(map[string]string)
	}
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(sessionActivitiesURL, sessionID), params)
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
	var sessionActivities sessionactivitiesmodels.IdsecSMSessionActivities
	err = mapstructure.Decode(sessionActivitiesJSON, &sessionActivities)
	if err != nil {
		return nil, err
	}
	return &sessionActivities, nil
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

func decodeSessionActivitiesFromResultMap(resultMap map[string]interface{}) ([]*sessionactivitiesmodels.IdsecSMSessionActivity, error) {
	items, err := pagination.ExtractItemsFromResult(resultMap, "session activities", "activities")
	if err != nil {
		return nil, err
	}
	var activities []*sessionactivitiesmodels.IdsecSMSessionActivity
	if err := mapstructure.Decode(items, &activities); err != nil {
		return nil, fmt.Errorf("failed to decode session activities: %w", err)
	}
	return activities, nil
}

// listPagedSessionActivities retrieves the activities by session ID.
func (s *IdsecSMSessionActivitiesService) listPagedSessionActivities(sessionID string) (<-chan *IdsecSMSessionActivitiesPage, error) {
	return pagination.ListAllPaginated[sessionactivitiesmodels.IdsecSMSessionActivity](
		context.Background(),
		pagination.HTTPGetFetch(s.ISPClient(), fmt.Sprintf(sessionActivitiesURL, sessionID), map[string]string{}),
		pagination.ListPaginatedConfig[sessionactivitiesmodels.IdsecSMSessionActivity]{
			ResourceName: "session activities",
			Decode:       decodeSessionActivitiesFromResultMap,
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

// List retrieves the activities of a session by its ID.
func (s *IdsecSMSessionActivitiesService) List(sessionActivities *sessionactivitiesmodels.IdsecSIASMGetSessionActivities) (<-chan *IdsecSMSessionActivitiesPage, error) {
	return s.listPagedSessionActivities(sessionActivities.SessionID)
}

// Count retrieves the count of all session activities by session id.
func (s *IdsecSMSessionActivitiesService) Count(activities *sessionactivitiesmodels.IdsecSIASMGetSessionActivities) (int, error) {
	sessionActivities, err := s.callListSessionActivities(activities.SessionID, nil)
	if err != nil {
		s.Logger.Error("failed counting session activities: %v", err)
		return 0, err
	}
	return sessionActivities.ReturnedCount, err
}

// ListBy retrieves the activities of a session by its ID and applies an optional filter.
func (s *IdsecSMSessionActivitiesService) ListBy(filter *sessionactivitiesmodels.IdsecSMSessionActivitiesFilter) (<-chan *IdsecSMSessionActivitiesPage, error) {
	pagedSessionActivities, err := s.listPagedSessionActivities(filter.SessionID)
	if err != nil {
		s.Logger.Error("failed to list session activities: %v", err)
		return nil, err
	}

	filteredItems := make([]*sessionactivitiesmodels.IdsecSMSessionActivity, 0)
	for page := range pagedSessionActivities {
		for _, activity := range page.Items {
			if filter.CommandContains == "" || strings.Contains(activity.Command, filter.CommandContains) {
				filteredItems = append(filteredItems, activity)
			}
		}
	}

	out := make(chan *IdsecSMSessionActivitiesPage, 1)
	out <- &IdsecSMSessionActivitiesPage{Items: filteredItems}
	close(out)
	return out, nil
}

// CountBy retrieves the count of all session activities by session id and applies an optional filter.
func (s *IdsecSMSessionActivitiesService) CountBy(filter *sessionactivitiesmodels.IdsecSMSessionActivitiesFilter) (int, error) {
	pagedSessionActivities, err := s.ListBy(filter)
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

// ServiceConfig returns the service configuration for the IdsecSMSessionActivitiesService.
func (s *IdsecSMSessionActivitiesService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
