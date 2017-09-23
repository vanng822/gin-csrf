package csrf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
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

func TestFlow(t *testing.T) {
	router := gin.Default()
	options := DefaultOptions()
	options.MaxUsage = 10
	options.MaxAge = 15 * 60
	store, _ := sessions.NewRedisStore(10, "tcp", "localhost:6379", "", []byte("asdsd"))
	router.Use(sessions.Sessions("session", store))
	router.Use(Csrf(options))
	router.GET("/", func(c *gin.Context) {
	})
	router.POST("/", func(c *gin.Context) {
	})
	ts := httptest.NewServer(router)
	defer ts.Close()
	resp, _ := http.Get(ts.URL)
	assert.Equal(t, 200, resp.StatusCode)
	resp, _ = http.Post(ts.URL, "application/json", strings.NewReader(""))
	assert.Equal(t, 400, resp.StatusCode)
}
