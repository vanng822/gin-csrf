package csrf

type Options struct {
	MaxUsage          int
	MaxAge            int
	CookieName        string
	HeaderName        string
	Secure            bool
	CsrfAlwaysRequire bool
}

func DefaultOptions() *Options {
	return &Options{
		MaxUsage:          100,
		MaxAge:            60 * 60,
		CookieName:        "csrf_token",
		HeaderName:        "X-CSRF-Token",
		Secure:            true,
		CsrfAlwaysRequire: false,
	}
}
