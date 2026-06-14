package internal

import (
	"fmt"
	"net/url"
	"strings"

	idseccommon "github.com/cyberark/idsec-sdk-golang/pkg/common"
)

// NextLinkFromResultMap returns the OData-style next page link from a PVWA list response body.
func NextLinkFromResultMap(resultMap map[string]interface{}) (string, bool) {
	for _, key := range []string{"next_link", "nextLink"} {
		if v, ok := resultMap[key].(string); ok && v != "" {
			return v, true
		}
	}
	return "", false
}

// QueryFromNextLink parses a PVWA next-link URL into query parameters for the following list request.
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

// DrainPages collects all items from paginated list channels into a single slice.
func DrainPages[T any](pages <-chan *idseccommon.IdsecPage[T], errCh <-chan error) ([]*T, error) {
	items := make([]*T, 0)
	for page := range pages {
		items = append(items, page.Items...)
	}
	if err := <-errCh; err != nil {
		return nil, err
	}
	return items, nil
}

// ExtractItemsFromResult returns the list payload from a PVWA OData-style JSON object.
//
// Parameters:
//   - resultMap: decoded list response object
//   - resourceName: used in error messages (e.g. "accounts", "safes")
//   - alternateKeys: optional extra top-level keys to try when "value" is absent (e.g. "Safes")
func ExtractItemsFromResult(resultMap map[string]interface{}, resourceName string, alternateKeys ...string) ([]interface{}, error) {
	if value, ok := resultMap["value"]; ok {
		items, ok := value.([]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to list %s: unexpected value field type %T", resourceName, value)
		}
		return items, nil
	}
	for _, key := range alternateKeys {
		if data, ok := resultMap[key]; ok {
			items, ok := data.([]interface{})
			if !ok {
				return nil, fmt.Errorf("failed to list %s: unexpected %s field type %T", resourceName, key, data)
			}
			return items, nil
		}
	}
	if len(alternateKeys) > 0 {
		return nil, fmt.Errorf(
			"failed to list %s: missing value or %s in response",
			resourceName,
			strings.Join(alternateKeys, " or "),
		)
	}
	return nil, fmt.Errorf("failed to list %s: missing value in response", resourceName)
}
