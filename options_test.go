package csrf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultOptions(t *testing.T) {
	actual := DefaultOptions()
	expected := &Options{
		MaxUsage:         100,
		MaxAge:           60 * 60,
		CookieName:       "csrf_token",
		HeaderName:       "X-CSRF-Token",
		Secure:           true,
		UsageCounterName: "csrf_token_usage",
		SessionName:      "csrf_token_session",
		IssuedName:       "csrf_token_issued",
		ByteLength:       32,
		Path:             "/",
		SafeMethods:      []string{"GET", "HEAD", "OPTIONS"},
	}
	assert.Equal(t, expected, actual)
}
