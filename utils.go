package tinyoidc

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
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

// validateEndpoint reports whether raw is a URL we're willing to send requests — and,
// for the token endpoint, the client_secret — to. It must be absolute and https, with
// an escape hatch for plaintext loopback so a local test OP like Dex works.
//
// Deliberately no check that the endpoint shares the issuer's origin: real OPs split
// them across hosts. Google's issuer is accounts.google.com while its token endpoint
// is oauth2.googleapis.com.
func validateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Host == "" {
		return fmt.Errorf("not an absolute URL: %q", raw)
	}
	// Credentials in the URL would be sent to the OP and logged along the way.
	if u.User != nil {
		return fmt.Errorf("URL carries userinfo")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("plaintext http is only allowed for loopback, got %q", u.Host)
	default:
		return fmt.Errorf("scheme %q is not http(s)", u.Scheme)
	}
}

// isLoopbackHost reports whether host names this machine, and so whether plaintext
// traffic to it stays off the network.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func getWithTimeout(uri string, timeout time.Duration) (*http.Response, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(uri)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", uri, resp.Status)
	}
	return resp, nil
}
