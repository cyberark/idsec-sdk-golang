package pamshaccounts

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshaccounts/models"
)

// decodePamshAccountFromMap decodes a snake_case PVWA account map into IdsecPamshAccount.
//
// PVWA nests secret_management, which maps onto the SecretManagement pointer field.
func decodePamshAccountFromMap(accountMap map[string]interface{}) (*accountsmodels.IdsecPamshAccount, error) {
	var account accountsmodels.IdsecPamshAccount
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName: "mapstructure",
		Result:  &account,
	})
	if err != nil {
		return nil, err
	}
	if err := decoder.Decode(accountMap); err != nil {
		return nil, err
	}
	return &account, nil
}

// decodePamshAccountsFromMaps decodes a slice of PVWA account maps for list pagination.
func decodePamshAccountsFromMaps(rawItems []interface{}) ([]*accountsmodels.IdsecPamshAccount, error) {
	items := make([]*accountsmodels.IdsecPamshAccount, 0, len(rawItems))
	for _, raw := range rawItems {
		itemMap, ok := raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to list accounts: unexpected entry type %T", raw)
		}
		account, err := decodePamshAccountFromMap(itemMap)
		if err != nil {
			return nil, err
		}
		items = append(items, account)
	}
	return items, nil
}
