package tinyoidc

import (
	"net/http"
	"net/url"
	"strings"
)

// isLocalPath reports whether next is a path on this site, and so safe to redirect to
// after login. Anything else is a potential open redirect.
func isLocalPath(next string) bool {
	// "//evil" and "/\\evil" are scheme-relative URLs to browsers.
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\") {
		return false
	}
	for _, c := range next {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	u, err := url.Parse(next)
	return err == nil && u.Scheme == "" && u.Host == ""
}

// isNavigation reports whether r is a browser loading a page, as opposed to fetch/XHR,
// a subresource, or an API client. Only navigations should be sent through a login flow:
// fetch() would silently follow the redirect to the OP's HTML and fail on CORS.
func isNavigation(r *http.Request) bool {
	// A redirected POST loses its body, so only GET and HEAD can resume after login.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	// Browsers set Sec-Fetch-* themselves and scripts can't forge it.
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate" && r.Header.Get("Sec-Fetch-Dest") == "document"
	}
	// No Sec-Fetch-*: an older browser or a non-browser client. Only an explicit
	// text/html counts; curl's default */* does not.
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}
