package internal

import (
	"errors"
	"fmt"
	"net/url"
)

// ErrUnexpectedListResult is returned when a list API response has an unexpected JSON shape.
var ErrUnexpectedListResult = errors.New("unexpected list result")

// NextLinkFromResultMap returns the OData-style next page link from a pCloud list response body.
func NextLinkFromResultMap(resultMap map[string]interface{}) (string, bool) {
	for _, key := range []string{"next_link", "nextLink"} {
		if v, ok := resultMap[key].(string); ok && v != "" {
			return v, true
		}
	}
	return "", false
}

// QueryFromNextLink parses a pCloud next-link URL into query parameters for the following list request.
func QueryFromNextLink(nextLink string) (map[string]string, error) {
	nextQuery, err := url.Parse(nextLink)
	if err != nil {
		return nil, fmt.Errorf("invalid nextLink: %w", err)
	}
	queryValues := nextQuery.Query()
	query := make(map[string]string, len(queryValues))
	for key, values := range queryValues {
		if len(values) > 0 {
			query[key] = values[0]
		}
	}
	return query, nil
}
