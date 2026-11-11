package keys

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// AppParam is the path parameter Internal reads the application from.
const AppParam = "app"

// Internal guards a service's internal API for luna-dashboard,
// /internal/v1/apps/{app}/…: the service token in Authorization: Bearer
// (the secret the service also uses towards the dashboard), compared in
// constant time. The application comes from the path, so the service's
// /v1 handlers run unchanged, as if a server key of that application with
// the given scopes had called (FromContext). The dashboard checks that the
// signed-in developer owns the application before it calls.
//
// Mount it on a route group whose pattern has {app}: it reads
// r.PathValue(AppParam), so it must run after routing.
func Internal(token string, scopes ...Scope) func(http.Handler) http.Handler {
	want := []byte(token)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scheme, got, _ := strings.Cut(r.Header.Get("Authorization"), " ")
			if token == "" || !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(got)), want) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="internal"`)
				deny(w, http.StatusUnauthorized, "missing or invalid service token")
				return
			}
			app := strings.ToLower(r.PathValue(AppParam))
			if !UUIDLike(app) {
				deny(w, http.StatusNotFound, "no such application")
				return
			}
			k := &Key{AppID: app, AppName: "", Kind: Server, Scopes: append([]Scope(nil), scopes...)}
			next.ServeHTTP(w, r.WithContext(WithKey(r.Context(), k)))
		})
	}
}

// UUIDLike reports whether s is a UUID in its canonical lower-case form
// (8-4-4-4-12 hex digits).
func UUIDLike(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f'):
			return false
		}
	}
	return true
}
