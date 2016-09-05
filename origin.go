package csrf

import "net/url"

func originOK(u *url.URL) bool {
	if u.Scheme == "" || u.Host == "" {
		return false
	}
	return true
}

func sameOrigin(a, b *url.URL) bool {
	if !originOK(a) || !originOK(b) {
		return false
	}
	return (a.Scheme == b.Scheme && a.Host == b.Host)
}
