package internal

// cceVersionNotSentLogValue is logged in place of the CCE version when it is omitted from the request.
const cceVersionNotSentLogValue = "unchanged, not sent"

// CCEVersionIfChanged returns the CCE version to send in an add/update-services request: the desired
// version when it is set and differs from the currently deployed one, or an empty string (omitted from
// the request) otherwise.
//
// The API reads the mere presence of a cceVersion as a request to upgrade `cce`, and validates it
// against the upgrade feature flag alongside the already-onboarded services in the payload. Since
// cce_version is computed, Terraform carries the deployed value in state and passes it back on every
// update, so echoing it unchanged would make an ordinary service upgrade fail with
// 501 FEATURE_NOT_IMPLEMENTED on 'cce'.
func CCEVersionIfChanged(desired, current string) string {
	if desired == "" || desired == current {
		return ""
	}
	return desired
}

// CCEVersionLogValue returns a human-readable description of the CCE version being sent, for logging.
func CCEVersionLogValue(cceVersionToSend string) string {
	if cceVersionToSend == "" {
		return cceVersionNotSentLogValue
	}
	return cceVersionToSend
}
