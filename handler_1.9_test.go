package csrf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/redis"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHttpsNoReferer(t *testing.T) {
	router := gin.Default()
	options := DefaultOptions()
	options.MaxUsage = 10
	options.MaxAge = 15 * 60
	store, _ := redis.NewStore(10, "tcp", "localhost:6379", "", "", []byte("something"))
	router.Use(sessions.Sessions("session", store))
	router.Use(func(c *gin.Context) {
		c.Request.URL.Scheme = "https"
		c.Request.Header.Del("Referer")
	})
	router.Use(Csrf(options))
	ts := httptest.NewTLSServer(router)
	defer ts.Close()

	client := ts.Client()
	resp, _ := client.Post(ts.URL, "application/json", strings.NewReader(""))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHttpsSameReferer(t *testing.T) {
	router := gin.Default()
	options := DefaultOptions()
	options.MaxUsage = 10
	options.MaxAge = 15 * 60
	store, _ := redis.NewStore(10, "tcp", "localhost:6379", "", "", []byte("something"))
	router.Use(sessions.Sessions("session", store))
	router.Use(func(c *gin.Context) {
		c.Request.URL.Scheme = "https"
		c.Request.URL.Host = "127.0.0.1"
		c.Request.Header.Set("Referer", c.Request.URL.String())
	})

	router.Use(Csrf(options))
	router.POST("/", func(c *gin.Context) {})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()

	client := ts.Client()
	resp, _ := client.Post(ts.URL, "application/json", strings.NewReader(""))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	cookies := resp.Cookies()
	sessionCookie, csrfCookie := testFetchCookies(cookies, options)

	assert.Equal(t, 400, resp.StatusCode)
	req, _ := http.NewRequest("POST", ts.URL, strings.NewReader(""))
	testAddCookies(sessionCookie, csrfCookie, req, options)
	resp, _ = client.Do(req)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestHttpsDifferentReferer(t *testing.T) {
	router := gin.Default()
	options := DefaultOptions()
	options.MaxUsage = 10
	options.MaxAge = 15 * 60
	store, _ := redis.NewStore(10, "tcp", "localhost:6379", "", "", []byte("something"))
	router.Use(sessions.Sessions("session", store))
	router.Use(func(c *gin.Context) {
		c.Request.URL.Scheme = "https"
		c.Request.URL.Host = "127.0.0.1"
		c.Request.Header.Set("Referer", "http://some.domain.tld")
	})
	router.Use(Csrf(options))
	ts := httptest.NewTLSServer(router)
	defer ts.Close()

	client := ts.Client()
	resp, _ := client.Post(ts.URL, "application/json", strings.NewReader(""))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// func TestHttpsBrokenReferer(t *testing.T) {
// 	router := gin.Default()
// 	options := DefaultOptions()
// 	options.MaxUsage = 10
// 	options.MaxAge = 15 * 60
// 	store, _ := sessions.NewRedisStore(10, "tcp", "localhost:6379", "", []byte("something"))
// 	router.Use(sessions.Sessions("session", store))
// 	router.Use(func(c *gin.Context) {
// 		c.Request.URL.Scheme = "https"
// 		// url.Parse always ok
// 		c.Request.Header.Set("Referer", "?????")
// 	})
// 	router.Use(Csrf(options))
// 	ts := httptest.NewTLSServer(router)
// 	defer ts.Close()
//
// 	client := ts.Client()
// 	resp, _ := client.Post(ts.URL, "application/json", strings.NewReader(""))
// 	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
// }
