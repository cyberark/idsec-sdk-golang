package pamshaccounts

import "fmt"

var pamshAccountUpdateNestedBlocks = map[string]struct{}{
	"secretManagement": {},
}

var pamshAccountUpdateExcludedPatchFields = map[string]struct{}{
	"id":     {},
	"secret": {},
}

// pamshAccountUpdateExcludedPatchPaths lists read-only flattened nested fields
// that must never be sent in a PVWA PATCH body (the API rejects them with PASWS125E).
var pamshAccountUpdateExcludedPatchPaths = map[string]struct{}{
	"secretManagement/lastModifiedTime": {},
}

// flattenPamshAccountUpdatePayload converts a camelCase serialized update-account map
// into flat PATCH field keys such as secretManagement/automaticManagementEnabled.
func flattenPamshAccountUpdatePayload(payload map[string]interface{}) map[string]interface{} {
	flat := make(map[string]interface{})
	for key, val := range payload {
		if _, excluded := pamshAccountUpdateExcludedPatchFields[key]; excluded {
			continue
		}
		if nested, ok := val.(map[string]interface{}); ok {
			if _, isNestedBlock := pamshAccountUpdateNestedBlocks[key]; isNestedBlock {
				for nestedKey, nestedVal := range nested {
					flatKey := fmt.Sprintf("%s/%s", key, nestedKey)
					if _, excluded := pamshAccountUpdateExcludedPatchPaths[flatKey]; excluded {
						continue
					}
					flat[flatKey] = nestedVal
				}
				continue
			}
		}
		flat[key] = val
	}
	return flat
}

// buildPamshAccountPatchOperations builds PVWA JSON Patch replace operations from a serialized update payload.
func buildPamshAccountPatchOperations(payload map[string]interface{}) []map[string]interface{} {
	flat := flattenPamshAccountUpdatePayload(payload)
	operations := make([]map[string]interface{}, 0, len(flat))
	for key, val := range flat {
		operations = append(operations, map[string]interface{}{
			"op":    "replace",
			"path":  fmt.Sprintf("/%s", key),
			"value": val,
		})
	}
	return operations
}
