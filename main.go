package main

import (
	"log/slog"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	rp, err := NewOidcRelyingParty(DEFAULT_PORT)
	if err != nil {
		slog.Error("server error", "err", err)
		return
	}

	if err := rp.ListenAndServe(); err != nil {
		slog.Error("server error", "err", err)
	}
}
