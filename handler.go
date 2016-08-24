package csrf

import (
	"net/http"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
)

var safeMethods = []string{"GET", "HEAD", "OPTIONS"}

// Csrf ...
func Csrf(maxUsage int, secure, httpOnly bool) gin.HandlerFunc {
	cookieName := "csrf_token"
	headerName := "X-CSRF-Token"
	counterName := "csrf_token_counter"
	sessionName := "csrf_token_session"
	byteLenth := 32
	maxAge := 60 * 60
	path := "/"

	return func(c *gin.Context) {
		session := sessions.Default(c)
		ct := session.Get(counterName)
		csrfSess := session.Get(sessionName)

		var (
			counter        = 0
			csrfSession    string
			newCsrfSession bool
		)

		defer func() {
			if newCsrfSession {
				session.Set(sessionName, csrfSession)
				// make sure reset counter
				session.Set(counterName, 0)
			}
			session.Save()
		}()

		csrfCookie, err := c.Cookie(cookieName)
		if err != nil || csrfCookie == "" {
			csrfSession = newCsrf(c, cookieName, path, maxAge, byteLenth, secure, httpOnly)
			newCsrfSession = true
		}

		if isMethodSafe(c.Request.Method) {
			c.Next()
			return
		}

		if ct != nil {
			counter = ct.(int)
		}

		if csrfSess != nil {
			csrfSession = csrfSess.(string)
		}

		// max usage generate new token
		if counter > maxUsage {
			csrfSession = newCsrf(c, cookieName, path, maxAge, byteLenth, secure, httpOnly)
			newCsrfSession = true
		}
		// compare session with header
		csrfHeader := c.Request.Header.Get(headerName)
		if csrfSession != csrfHeader {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": cookieName})
			c.Abort()
			return
		}
		session.Set(counterName, counter+1)
		c.Next()
	}
}

func newCsrf(c *gin.Context, cookieName, path string, maxAge, byteLenth int, secure, httpOnly bool) string {
	csrfCookie := randomHex(byteLenth)
	c.SetCookie(cookieName, csrfCookie, maxAge, path, "", secure, httpOnly)
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
