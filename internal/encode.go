package internal

import (
	"net/url"
	"sort"
	"strings"
)

// queryEscape encodes a string for use in a URL query, using %20 instead of +
// for spaces. This is necessary to correctly render spaces in some authenticator
// apps, like Google Authenticator, while still properly escaping & and = characters
// to prevent parameter injection.
func queryEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// EncodeQuery encodes url.Values into a query string sorted by key, using %20
// instead of + to encode spaces. No trailing ampersand is appended.
// This is the standard encoding suitable for most authenticator apps.
func EncodeQuery(v url.Values) string {
	return EncodeQueryTrailing(v, false)
}

// EncodeQueryTrailing encodes url.Values into a query string sorted by key.
// If trailingAmpersand is true, appends a trailing '&' to work around a Google
// Authenticator QR code parsing bug where it may fail to parse the secret
// parameter when it is the last (trailing) query parameter.
// See: https://github.com/pquerna/otp/issues/94
func EncodeQueryTrailing(v url.Values, trailingAmpersand bool) string {
	if v == nil {
		return ""
	}
	var buf strings.Builder
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vs := v[k]
		keyEscaped := queryEscape(k)
		for _, v := range vs {
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(keyEscaped)
			buf.WriteByte('=')
			buf.WriteString(queryEscape(v))
		}
	}
	if trailingAmpersand && buf.Len() > 0 {
		buf.WriteByte('&')
	}
	return buf.String()
}
