package csrf

import (
	"crypto/subtle"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// Csrf ...
func Csrf(options *Options) gin.HandlerFunc {
	if options == nil {
		options = DefaultOptions()
	}

	return func(c *gin.Context) {
		var (
			counter     = 0
			csrfSession string
			issued      int64
		)

		if slices.Contains(options.SafeMethods, c.Request.Method) {
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
		session := sessions.Default(c)
		csrfCookie, _ := c.Cookie(options.CookieName)

		if csrfCookie == "" {
			Logger.Info("csrf_token not found in cookie")
			generateNewCsrfTokenAndHandle(c, session, options)
			return
		}

		if csrfSess := session.Get(options.SessionName); csrfSess != nil {
			csrfSession = csrfSess.(string)
		}

		if csrfSession == "" {
			Logger.Info("csrf_token not found in session")
			generateNewCsrfTokenAndHandle(c, session, options)
			return
		}

		if ct := session.Get(options.UsageCounterName); ct != nil {
			counter = ct.(int)
		}
		// max usage generate new token
		if counter >= options.MaxUsage {
			Logger.Info("csrf_token max usage. New token required")
			generateNewCsrfTokenAndHandle(c, session, options)
			return
		}

		now := time.Now()
		if is := session.Get(options.IssuedName); is != nil {
			issued = is.(int64)
		}
		if now.Unix() > (issued + int64(options.MaxAge)) {
			Logger.Info("csrf_token max age. New token required")
			generateNewCsrfTokenAndHandle(c, session, options)
			return
		}

		// compare session with header
		csrfHeader := c.Request.Header.Get(options.HeaderName)
		//log.Println("sess", csrfSession, "cookie", csrfCookie, "csrfHeader", csrfHeader, counter, options.MaxUsage)
		if !isTokenValid(csrfSession, csrfHeader) {
			Logger.Info("csrf_token diff. New token required")
			generateNewCsrfTokenAndHandle(c, session, options)
			return
		}
		session.Set(options.UsageCounterName, counter+1)
		defer saveSession(session, options, csrfSession, false)
		c.Next()
	}
}

func isTokenValid(csrfSession, csrfHeader string) bool {
	return subtle.ConstantTimeCompare([]byte(csrfSession), []byte(csrfHeader)) == 1
}

func saveSession(session sessions.Session, options *Options, csrfSession string, newCsrfSession bool) {
	if newCsrfSession {
		session.Set(options.SessionName, csrfSession)
		// make sure reset counter
		session.Set(options.UsageCounterName, 0)
		session.Set(options.IssuedName, time.Now().Unix())
	}
	session.Save()
}

func generateNewCsrfTokenAndHandle(c *gin.Context, session sessions.Session, options *Options) {
	newCsrfToken, err := generateToken(options.ByteLength)
	if err != nil {
		handleError(c, http.StatusInternalServerError, gin.H{"status": "error", "error": "internal error"})
		return
	}
	// set cookie
	c.SetCookie(options.CookieName, newCsrfToken, options.MaxAge, options.Path, "", options.Secure, false)

	saveSession(session, options, newCsrfToken, true)

	// bad request and error=CookieName for challenging the client to retry with new token
	handleError(c, http.StatusBadRequest, gin.H{"status": "error", "error": options.CookieName})
}

func handleError(c *gin.Context, statusCode int, message gin.H) {
	c.Abort()
	c.JSON(statusCode, message)
}
