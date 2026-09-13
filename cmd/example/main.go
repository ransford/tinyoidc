// Command example is a tiny site with one public page and one page behind
// tinyoidc. Start Dex first (dev/dex/run.sh), then visit
// http://localhost:8192/.
package main

import (
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/ransford/tinyoidc"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	rp, err := tinyoidc.NewOidcRelyingParty(tinyoidc.DEFAULT_PORT)
	if err != nil {
		slog.Error("setup error", "err", err)
		return
	}

	// header starts an HTML page with a one-line login status.
	header := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<header><a href="/">Home</a> · <a href="/private">Private page</a> · `)
		if claims, ok := rp.Claims(r); ok {
			fmt.Fprintf(w, `Logged in as %s · <form method="post" action="/auth/logout" style="display:inline"><button>Log out</button></form>`, html.EscapeString(claims.Email))
		} else {
			login := "/auth/login?" + url.Values{"next": {r.URL.RequestURI()}}.Encode()
			fmt.Fprintf(w, `Not logged in · <a href="%s">Log in</a>`, html.EscapeString(login))
		}
		fmt.Fprint(w, "</header><hr>\n")
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", rp.Handler())
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		header(w, r)
		fmt.Fprint(w, `<p>Public page.</p>
<p><button id="whoami">fetch /api/whoami</button> <code id="result"></code></p>
<script>
document.getElementById("whoami").onclick = async () => {
	const resp = await fetch("/api/whoami");
	document.getElementById("result").textContent = resp.status + " " + await resp.text();
};
</script>`)
	})
	mux.Handle("GET /private", rp.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header(w, r)
		claims, _ := tinyoidc.ClaimsFromContext(r.Context())
		fmt.Fprintf(w, "<p>Private page. iss=%s, sub=%s</p>",
			html.EscapeString(claims.Issuer), html.EscapeString(claims.Subject))
	})))

	mux.Handle("GET /api/whoami", rp.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := tinyoidc.ClaimsFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"iss": claims.Issuer, "sub": claims.Subject, "email": claims.Email})
	})))

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", tinyoidc.DEFAULT_PORT),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		Handler:      mux,
	}
	slog.Info("starting server", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server error", "err", err)
	}
}
