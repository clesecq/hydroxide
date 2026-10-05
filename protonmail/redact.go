package protonmail

import (
	"encoding/json"
	"strings"
)

const redactedValue = "[redacted]"

// redactedJSONFields lists the JSON object keys whose values must never end up
// in debug logs: credentials, SRP material, session tokens, key material and
// human verification tokens.
var redactedJSONFields = map[string]bool{
	"accesstoken":            true,
	"refreshtoken":           true,
	"humanverificationtoken": true,
	"token":                  true,
	"clientephemeral":        true,
	"clientproof":            true,
	"serverephemeral":        true,
	"serverproof":            true,
	"salt":                   true,
	"keysalt":                true,
	"privatekey":             true,
	"password":               true,
	"loginpassword":          true,
	"mailboxpassword":        true,
	"twofactorcode":          true,
	"cookie":                 true,
}

// redactJSON returns b with the values of sensitive fields replaced. If b isn't
// valid JSON it is replaced entirely, as we can't tell what it holds.
func redactJSON(b []byte) []byte {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return []byte(`"` + redactedValue + `"`)
	}

	out, err := json.Marshal(redactValue(v))
	if err != nil {
		return []byte(`"` + redactedValue + `"`)
	}
	return out
}

// redactValueOf marshals v to JSON and redacts its sensitive fields.
func redactValueOf(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`"` + redactedValue + `"`)
	}
	return redactJSON(b)
}

func redactValue(v interface{}) interface{} {
	switch v := v.(type) {
	case map[string]interface{}:
		for k, sub := range v {
			if redactedJSONFields[strings.ToLower(k)] {
				if sub != nil {
					v[k] = redactedValue
				}
				continue
			}
			v[k] = redactValue(sub)
		}
		return v
	case []interface{}:
		for i, sub := range v {
			v[i] = redactValue(sub)
		}
		return v
	default:
		return v
	}
}
