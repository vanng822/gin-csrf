package csrf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsMethodSafeTrue(t *testing.T) {
	assert.True(t, isMethodSafe("GET", []string{"GET", "OPTIONS"}))
}

func TestIsMethodSafeFalse(t *testing.T) {
	assert.False(t, isMethodSafe("POST", []string{"GET", "OPTIONS"}))
}

func TestIsTokenValidTrue(t *testing.T) {
	assert.True(t, isTokenValid("abc", "abc"))
}

func TestIsTokenValidFalse(t *testing.T) {
	assert.False(t, isTokenValid("abc", "bcf"))
}
