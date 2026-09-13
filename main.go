package main

import (
	"log/slog"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	if err := NewOidcRelyingParty(DEFAULT_PORT).ListenAndServe(); err != nil {
		slog.Error("server error", "err", err)
	}
}
