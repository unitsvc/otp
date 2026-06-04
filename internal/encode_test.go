package internal

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeQueryBasic(t *testing.T) {
	v := url.Values{}
	v.Set("secret", "JBSWY3DPEHPK3PXP")
	v.Set("issuer", "Example")

	result := EncodeQuery(v)
	require.Contains(t, result, "issuer=Example")
	require.Contains(t, result, "secret=JBSWY3DPEHPK3PXP")
	// Default EncodeQuery does NOT append trailing &
	require.False(t, strings.HasSuffix(result, "&"), "should not end with trailing & by default")
}

func TestEncodeQuerySpaces(t *testing.T) {
	v := url.Values{}
	v.Set("issuer", "Snake Oil")

	result := EncodeQuery(v)
	require.Contains(t, result, "issuer=Snake%20Oil")
	require.NotContains(t, result, "issuer=Snake+Oil")
}

func TestEncodeQuerySortsKeys(t *testing.T) {
	v := url.Values{}
	v.Set("zebra", "z")
	v.Set("alpha", "a")
	v.Set("middle", "m")

	result := EncodeQuery(v)
	// Keys should be sorted: alpha, middle, zebra (no trailing & by default)
	require.Regexp(t, `alpha=a&.*middle=m&.*zebra=z`, result)
}

func TestEncodeQueryNil(t *testing.T) {
	result := EncodeQuery(nil)
	require.Equal(t, "", result)
}

func TestEncodeQueryParameterInjection(t *testing.T) {
	v := url.Values{}
	v.Set("secret", "REALSECRET")
	v.Set("image", "https://evil.com/img.png&secret=FAKE")

	result := EncodeQuery(v)
	// The & in the image URL must be escaped, not treated as a separator
	require.NotContains(t, result, "secret=FAKE", "Parameter injection via & must be prevented")
	// The injected & should be encoded as %26
	require.Contains(t, result, "%26")
}

func TestEncodeQueryTrailingEnabled(t *testing.T) {
	v := url.Values{}
	v.Set("secret", "JBSWY3DPEHPK3PXP")
	v.Set("issuer", "Example")

	result := EncodeQueryTrailing(v, true)
	require.True(t, strings.HasSuffix(result, "&"), "should end with trailing & when enabled")
	require.Contains(t, result, "issuer=Example")
	require.Contains(t, result, "secret=JBSWY3DPEHPK3PXP")
}

func TestEncodeQueryTrailingDisabled(t *testing.T) {
	v := url.Values{}
	v.Set("secret", "JBSWY3DPEHPK3PXP")

	result := EncodeQueryTrailing(v, false)
	require.False(t, strings.HasSuffix(result, "&"), "should not end with trailing & when disabled")
}

func TestEncodeQueryTrailingNil(t *testing.T) {
	result := EncodeQueryTrailing(nil, true)
	require.Equal(t, "", result)
}

func TestSetExtraParams(t *testing.T) {
	v := url.Values{}
	v.Set("secret", "REAL")
	v.Set("issuer", "TestOrg")

	SetExtraParams(v, map[string]string{
		"source":  "mobile",
		"version": "2",
	}, 1024)

	require.Equal(t, "mobile", v.Get("source"))
	require.Equal(t, "2", v.Get("version"))
	// Reserved keys must NOT be overridden
	require.Equal(t, "REAL", v.Get("secret"), "secret must not be overridden")
	require.Equal(t, "TestOrg", v.Get("issuer"), "issuer must not be overridden")
}

func TestSetExtraParamsReservedKeys(t *testing.T) {
	v := url.Values{}
	v.Set("secret", "ORIG")

	SetExtraParams(v, map[string]string{
		"SECRET":    "fake",
		"Algorithm": "FAKE",
		"issuer":    "evil",
		"ok_key":    "good",
	}, 1024)

	require.Equal(t, "ORIG", v.Get("secret"))
	require.Equal(t, "", v.Get("Algorithm"))
	require.Equal(t, "good", v.Get("ok_key"))
}

func TestSetExtraParamsControlChars(t *testing.T) {
	v := url.Values{}
	SetExtraParams(v, map[string]string{
		"bad":  "value\r\ninjected",
		"null": "before\x00after",
		"good": "normal",
	}, 1024)

	// Control chars should be filtered
	_, hasBad := v["bad"]
	require.False(t, hasBad, "value with control chars should be filtered")
	_, hasNull := v["null"]
	require.False(t, hasNull, "value with null should be filtered")
	require.Equal(t, "normal", v.Get("good"))
}

func TestSetExtraParamsEmpty(t *testing.T) {
	v := url.Values{}
	SetExtraParams(v, nil, 1024)
	SetExtraParams(v, map[string]string{}, 1024)
	// Should not panic
}

func TestBuildLabelPath(t *testing.T) {
	// Normal: issuer in label (path has leading /)
	path, rawPath := BuildLabelPath("MyApp", "user@example.com", false)
	require.Equal(t, "/MyApp:user@example.com", path)
	require.NotEmpty(t, rawPath) // rawPath has escaped @

	// Omit issuer from label
	path2, rawPath2 := BuildLabelPath("MyApp", "user@example.com", true)
	require.Equal(t, "/user@example.com", path2)
	require.NotEmpty(t, rawPath2)

	// Special characters in issuer
	path3, rawPath3 := BuildLabelPath("My App", "user+tag@example.com", false)
	require.Contains(t, path3, "My App:")
	require.NotEmpty(t, rawPath3, "rawPath should be set for escaped characters")
}

func TestZeroBytes(t *testing.T) {
	buf := []byte{1, 2, 3, 4, 5}
	ZeroBytes(buf)
	require.Equal(t, []byte{0, 0, 0, 0, 0}, buf)

	// Nil should not panic
	ZeroBytes(nil)
	ZeroBytes([]byte{})
}

func TestSetExtraParamsOversizedValue(t *testing.T) {
	v := url.Values{}
	// Value exceeding maxLen=10 should be filtered
	SetExtraParams(v, map[string]string{
		"ok":   "short",
		"long": "this_value_is_way_too_long_for_maxLen",
	}, 10)

	require.Equal(t, "short", v.Get("ok"))
	_, hasLong := v["long"]
	require.False(t, hasLong, "oversized value should be filtered")
}

func TestSetExtraParamsEmptyKey(t *testing.T) {
	v := url.Values{}
	SetExtraParams(v, map[string]string{
		"":     "orphan",
		"good": "value",
	}, 1024)

	require.Equal(t, "value", v.Get("good"))
	_, hasEmpty := v[""]
	require.False(t, hasEmpty, "empty key should be filtered")
}
