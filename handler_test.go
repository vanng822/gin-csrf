package csrf

import (
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func testFetchCookies(cookies []*http.Cookie, options *Options) (sessionCookie *http.Cookie, csrfCookie *http.Cookie) {
	for _, c := range cookies {
		if c.Name == options.CookieName {
			csrfCookie = c
		} else if c.Name == "session" {
			sessionCookie = c
		}
	}
	return
}

func testAddCookies(sessionCookie *http.Cookie, csrfCookie *http.Cookie, req *http.Request, options *Options) {
	req.Header.Add("Cookie", sessionCookie.String())
	req.Header.Add("Cookie", csrfCookie.String())
	req.Header.Add(options.HeaderName, csrfCookie.Value)
}

func testSetup() (*gin.Engine, *Options) {
	router := gin.Default()
	options := DefaultOptions()
	options.MaxUsage = 10
	options.MaxAge = 15 * 60
	store, _ := sessions.NewRedisStore(10, "tcp", "localhost:6379", "", []byte("something"))
	router.Use(sessions.Sessions("session", store))
	router.Use(Csrf(options))
	router.GET("/", func(c *gin.Context) {
	})
	router.HEAD("/", func(c *gin.Context) {
	})
	router.OPTIONS("/", func(c *gin.Context) {
	})
	router.POST("/", func(c *gin.Context) {
	})
	router.PUT("/", func(c *gin.Context) {
	})
	router.DELETE("/", func(c *gin.Context) {
	})
	router.PATCH("/", func(c *gin.Context) {
	})
	return router, options
}

func TestCreateDefaultOptions(t *testing.T) {
	router := gin.Default()
	router.Use(Csrf(nil))
}

func TestSafeMethods(t *testing.T) {
	router, options := testSetup()
	ts := httptest.NewServer(router)
	defer ts.Close()
	for _, method := range options.SafeMethods {
		client := &http.Client{}
		req, _ := http.NewRequest(method, ts.URL, strings.NewReader(""))
		resp, _ := client.Do(req)
		assert.Equal(t, 200, resp.StatusCode)
	}
}

func TestActionMethods(t *testing.T) {
	router, options := testSetup()
	ts := httptest.NewServer(router)
	defer ts.Close()
	actionMethods := []string{"POST", "PUT", "PATCH", "DELETE"}

	for _, method := range actionMethods {
		resp, _ := http.Post(ts.URL, "application/json", strings.NewReader(""))
		cookies := resp.Cookies()
		sessionCookie, csrfCookie := testFetchCookies(cookies, options)
		assert.Equal(t, 400, resp.StatusCode)
		client := &http.Client{}
		req, _ := http.NewRequest(method, ts.URL, strings.NewReader(""))
		testAddCookies(sessionCookie, csrfCookie, req, options)
		resp, _ = client.Do(req)
		assert.Equal(t, 200, resp.StatusCode)
	}
}

func TestMaxUsage(t *testing.T) {
	router, options := testSetup()
	options.MaxUsage = 1
	ts := httptest.NewServer(router)
	defer ts.Close()

	resp, _ := http.Post(ts.URL, "application/json", strings.NewReader(""))
	cookies := resp.Cookies()
	sessionCookie, csrfCookie := testFetchCookies(cookies, options)
	assert.Equal(t, 400, resp.StatusCode)
	client := &http.Client{}
	req, _ := http.NewRequest("POST", ts.URL, strings.NewReader(""))
	testAddCookies(sessionCookie, csrfCookie, req, options)
	resp, _ = client.Do(req)
	assert.Equal(t, 200, resp.StatusCode)
	resp, _ = client.Do(req)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestInvalidSession(t *testing.T) {
	router, options := testSetup()
	options.MaxUsage = 1
	ts := httptest.NewServer(router)
	defer ts.Close()

	resp, _ := http.Post(ts.URL, "application/json", strings.NewReader(""))
	cookies := resp.Cookies()
	sessionCookie, csrfCookie := testFetchCookies(cookies, options)
	assert.Equal(t, 400, resp.StatusCode)
	client := &http.Client{}
	req, _ := http.NewRequest("POST", ts.URL, strings.NewReader(""))
	// causing not found session
	sessionCookie.Value = csrfCookie.Value
	req.Header.Add("Cookie", sessionCookie.String())
	req.Header.Add("Cookie", csrfCookie.String())
	req.Header.Set(options.HeaderName, sessionCookie.Value)
	resp, _ = client.Do(req)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestInvalidCsrfHeader(t *testing.T) {
	router, options := testSetup()
	options.MaxUsage = 1
	ts := httptest.NewServer(router)
	defer ts.Close()

	resp, _ := http.Post(ts.URL, "application/json", strings.NewReader(""))
	cookies := resp.Cookies()
	sessionCookie, csrfCookie := testFetchCookies(cookies, options)
	assert.Equal(t, 400, resp.StatusCode)
	client := &http.Client{}
	req, _ := http.NewRequest("POST", ts.URL, strings.NewReader(""))
	req.Header.Add("Cookie", sessionCookie.String())
	req.Header.Add("Cookie", csrfCookie.String())
	req.Header.Set(options.HeaderName, sessionCookie.Value)
	resp, _ = client.Do(req)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestIssuedTimePassed(t *testing.T) {
	router, options := testSetup()
	options.MaxAge = 1
	ts := httptest.NewServer(router)
	defer ts.Close()

	resp, _ := http.Post(ts.URL, "application/json", strings.NewReader(""))
	cookies := resp.Cookies()
	sessionCookie, csrfCookie := testFetchCookies(cookies, options)
	assert.Equal(t, 400, resp.StatusCode)
	client := &http.Client{}
	req, _ := http.NewRequest("POST", ts.URL, strings.NewReader(""))
	testAddCookies(sessionCookie, csrfCookie, req, options)
	time.Sleep(2 * time.Second)
	resp, _ = client.Do(req)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestHttpsNoReferer(t *testing.T) {
	router := gin.Default()
	options := DefaultOptions()
	options.MaxUsage = 10
	options.MaxAge = 15 * 60
	store, _ := sessions.NewRedisStore(10, "tcp", "localhost:6379", "", []byte("something"))
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
	store, _ := sessions.NewRedisStore(10, "tcp", "localhost:6379", "", []byte("something"))
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
	log.Println(cookies)
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
	store, _ := sessions.NewRedisStore(10, "tcp", "localhost:6379", "", []byte("something"))
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
