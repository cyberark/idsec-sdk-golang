package testutils

import (
	"bytes"
	"io"
	"net/http"
)

// NewMockResponse creates a mock HTTP response with the given status code and body.
func NewMockResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

// ListAssetsResponseJSON returns a sample JSON response for list assets.
func ListAssetsResponseJSON() string {
	return `{
		"assets": [
			{
				"assetCategory": "server",
				"assetType": "vm",
				"assetId": "asset-001",
				"name": "prod-server-1",
				"address": "10.0.0.1",
				"protocol": "SSH",
				"accessMethod": "vaulted",
				"isFavorite": true,
				"platformType": "UnixSSH"
			},
			{
				"assetCategory": "database",
				"assetType": "db",
				"assetId": "asset-002",
				"name": "prod-db-1",
				"address": "10.0.0.2",
				"protocol": "DB",
				"accessMethod": "zsp",
				"isFavorite": false,
				"platformType": "MySQL"
			}
		],
		"size": 2
	}`
}

// EmptyListAssetsResponseJSON returns a sample JSON response with no assets.
func EmptyListAssetsResponseJSON() string {
	return `{
		"assets": [],
		"size": 0
	}`
}

// SecretResponseJSON returns a sample JSON response for get secret.
func SecretResponseJSON() string {
	return `{
		"assetId": "asset-001",
		"secret": "s3cr3t-p@ssw0rd"
	}`
}
