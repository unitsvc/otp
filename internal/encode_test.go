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
