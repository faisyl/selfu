package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"runtime/debug"

	"selfu/internal/auth"
)

type reqIDKey struct{}

// withRequestID assigns a correlation id to every request.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			tok, err := auth.RandomToken(9)
			if err != nil {
				panic(err) // crypto/rand failure is unrecoverable
			}
			id = tok
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), reqIDKey{}, id)))
	})
}

func requestIDFrom(ctx context.Context) string {
	if id, ok := ctx.Value(reqIDKey{}).(string); ok {
		return id
	}
	return ""
}

// withRecoverer converts panics into 500 responses and logs the stack.
func withRecoverer(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Error("panic",
						"err", err,
						"stack", string(debug.Stack()),
						"request_id", requestIDFrom(r.Context()),
					)
					writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
