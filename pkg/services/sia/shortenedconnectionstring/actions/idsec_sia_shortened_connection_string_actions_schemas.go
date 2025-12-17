package actions

import siashortenedconnectionstring "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/shortenedconnectionstring/models"

// ActionToSchemaMap is a map that defines the mapping between Shortened connection string action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"generate": &siashortenedconnectionstring.IdsecSIAGenerateShortenedConnectionString{},
}
