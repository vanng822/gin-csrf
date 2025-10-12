package csrf

type Options struct {
	// maximum usage of csrf token
	MaxUsage int
	// maximum age for this token to live
	MaxAge int
	// name of the cookie to keep csrf token
	CookieName string
	// name of the header which the csrf token is sending back
	HeaderName string
	// for setting the cookie
	Secure bool
	// name for keeping usage counter in redis
	UsageCounterName string
	// name for keeping csrf token in redis session
	SessionName string
	// name for keeping issued time in redis
	IssuedName string
	// Length of csrf token
	ByteLength int
	// path which the cookie is valid
	Path string
	// Http methods considered as safe and pass validation
	SafeMethods []string
}

func DefaultOptions() *Options {
	return &Options{
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
}
