package contract

import "encoding/json"

// optionalValue decodes a request field that has to tell "absent" from JSON
// null. raw is the field as json.RawMessage captured it: empty when the
// field was not sent, the literal null when it was sent as null. Absent
// returns nil, leaving the stored value alone; anything else returns a
// pointer to the decoded value, so a present null is a *any holding nil,
// which only a json entry accepts. field names the request field in the
// refusal. It is the one place that decision is made, for flags and config
// alike.
func optionalValue(field string, raw json.RawMessage) (*any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, badRequest(field + " is not valid JSON")
	}
	return &v, nil
}
