package csrf

import (
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
)

var safeMethods = []string{"GET", "HEAD", "OPTIONS"}

// Csrf ...
func Csrf(options *Options) gin.HandlerFunc {
	if options == nil {
		options = DefaultOptions()
	}
	return func(c *gin.Context) {
		session := sessions.Default(c)
		var (
			counter        = 0
			csrfSession    string
			issued         int64
			newCsrfSession bool
		)

		saveSession := func() {
			if newCsrfSession {
				session.Set(options.SessionName, csrfSession)
				// make sure reset counter
				session.Set(options.UsageCounterName, 0)
				session.Set(options.IssuedName, time.Now().Unix())
			}
			session.Save()
		}

		csrfCookie, err := c.Cookie(options.CookieName)
		if err != nil || csrfCookie == "" {
			csrfSession = newCsrf(c, options.CookieName, options.Path, options.MaxAge, options.ByteLenth, options.Secure)
			newCsrfSession = true
		}

		if isMethodSafe(c.Request.Method) {
			c.Next()
			return
		}

		if c.Request.URL.Scheme == "https" {
			referer, err := url.Parse(c.Request.Header.Get("Referer"))
			if err != nil || referer == nil {
				handleError(c, http.StatusBadRequest, gin.H{})
				return
			}
			if !sameOrigin(c.Request.URL, referer) {
				handleError(c, http.StatusBadRequest, gin.H{})
				return
			}
		}

		if ct := session.Get(options.UsageCounterName); ct != nil {
			counter = ct.(int)
		}
		if csrfSess := session.Get(options.SessionName); csrfSess != nil {
			csrfSession = csrfSess.(string)
		}
		if is := session.Get(options.IssuedName); is != nil {
			issued = is.(int64)
		}
		now := time.Now()
		// max usage generate new token

		if counter >= options.MaxUsage {
			csrfSession = newCsrf(c, options.CookieName, options.Path, options.MaxAge, options.ByteLenth, options.Secure)
			newCsrfSession = true
		} else if now.Unix() > (issued + int64(options.MaxAge)) {
			csrfSession = newCsrf(c, options.CookieName, options.Path, options.MaxAge, options.ByteLenth, options.Secure)
			newCsrfSession = true
		}
		// compare session with header
		csrfHeader := c.Request.Header.Get(options.HeaderName)
		if csrfSession != csrfHeader {
			saveSession()
			handleError(c, http.StatusBadRequest, gin.H{"status": "error", "error": options.CookieName})
			return
		}
		session.Set(options.UsageCounterName, counter+1)
		defer saveSession()
		c.Next()
	}
}

func handleError(c *gin.Context, statusCode int, message gin.H) {
	c.JSON(statusCode, message)
	c.Abort()
}

func newCsrf(c *gin.Context, cookieName, path string, maxAge, byteLenth int, secure bool) string {
	csrfCookie := randomHex(byteLenth)
	c.SetCookie(cookieName, csrfCookie, maxAge, path, "", secure, false)
	return csrfCookie
}

func isMethodSafe(method string) bool {
	for _, m := range safeMethods {
		if method == m {
			return true
		}
	}
	return false
}
