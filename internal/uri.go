package internal

import (
	"net/url"
	"strings"
)

// reservedURIParams are parameter keys that ExtraParams may not override.
// The comparison is case-insensitive.
var reservedURIParams = map[string]bool{
	"secret":    true,
	"issuer":    true,
	"algorithm": true,
	"digits":    true,
	"period":    true,
	"encoder":   true,
	"counter":   true,
	"image":     true,
}

// SetExtraParams adds custom query parameters to v from extra, filtering out
// reserved keys (case-insensitive), empty keys, values exceeding maxLen,
// and values containing control characters (\r, \n, \x00).
func SetExtraParams(v url.Values, extra map[string]string, maxLen int) {
	for key, val := range extra {
		if key == "" {
			continue
		}
		if len(key) > maxLen || len(val) > maxLen {
			continue
		}
		if reservedURIParams[strings.ToLower(key)] {
			continue
		}
		// Reject values containing control characters
		if strings.ContainsAny(val, "\r\n\x00") {
			continue
		}
		v.Set(key, val)
	}
}

// BuildLabelPath constructs the path and rawPath for an otpauth:// URI.
// When omitIssuer is false (default), the label is "Issuer:AccountName".
// When omitIssuer is true, the label is only "AccountName".
func BuildLabelPath(issuer, accountName string, omitIssuer bool) (path, rawPath string) {
	if omitIssuer {
		rawPath = "/" + url.PathEscape(accountName)
		path = "/" + accountName
	} else {
		rawPath = "/" + url.PathEscape(issuer) + ":" + url.PathEscape(accountName)
		path = "/" + issuer + ":" + accountName
	}
	return path, rawPath
}
