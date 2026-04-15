// Package secretstores provides services for managing Secrets Hub secret stores.
package secretstores

import "fmt"

// StoreState represents the state of a secret store.
type StoreState string

const (
	// StateEnabled indicates the secret store is enabled.
	StateEnabled StoreState = "ENABLED"

	// StateDisabled indicates the secret store is disabled.
	StateDisabled StoreState = "DISABLED"
)

// StoreAction represents an action that can be performed on a secret store state.
type StoreAction string

const (
	// ActionEnable is the action to enable a secret store.
	ActionEnable StoreAction = "enable"

	// ActionDisable is the action to disable a secret store.
	ActionDisable StoreAction = "disable"
)

// stateToAction maps each actionable StoreState to its corresponding StoreAction.
var stateToAction = map[StoreState]StoreAction{
	StateEnabled:  ActionEnable,
	StateDisabled: ActionDisable,
}

// toAction converts a StoreState to its corresponding StoreAction.
func (s StoreState) toAction() (StoreAction, error) {
	action, ok := stateToAction[s]
	if !ok {
		return "", fmt.Errorf("invalid state: %s", s)
	}
	return action, nil
}
