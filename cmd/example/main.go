// Command example is a tiny site with one public page and one page behind
// tinyoidc. Start Dex first (dev/dex/run.sh), then visit
// http://localhost:8192/.
package main

import (
	"fmt"
	"log/slog"
	"net/http"
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

	mux := http.NewServeMux()
	mux.Handle("/auth/", rp.Handler())
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<p>Public page. <a href="/private">Private page</a> · <a href="/auth/logout">Log out</a></p>`)
	})
	mux.Handle("GET /private", rp.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := tinyoidc.ClaimsFromContext(r.Context())
		fmt.Fprintf(w, "Hello, %s (iss=%s, sub=%s)\n", claims.Email, claims.Issuer, claims.Subject)
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
