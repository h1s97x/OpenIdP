package middleware

import (
	"net/http"
)

// CSRF verifies the CSRF token header for state-changing requests.
// Tokens are minted on login/session fetch and stored in the TokenStore,
// optionally bound to the session cookie that issued them.
func CSRF(headerName string, store *TokenStore, sessionCookie string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}
			token := r.Header.Get(headerName)
			if token == "" {
				// Session cookie present but CSRF header missing => reject
				writeJSONError(w, r, http.StatusForbidden, "csrf.missing", "CSRF token is missing")
				return
			}
			session := ""
			if c, err := r.Cookie(sessionCookie); err == nil {
				session = c.Value
			}
			if !store.Check(token, session) {
				writeJSONError(w, r, http.StatusForbidden, "csrf.invalid", "Invalid CSRF token")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
