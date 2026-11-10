package keys

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

type keyCtx struct{}

// FromContext returns the key RequireKey accepted for the request.
func FromContext(ctx context.Context) (*Key, bool) {
	k, ok := ctx.Value(keyCtx{}).(*Key)
	return k, ok
}

// WithKey returns ctx carrying k (for tests and for the dashboard's own
// handlers).
func WithKey(ctx context.Context, k *Key) context.Context {
	return context.WithValue(ctx, keyCtx{}, k)
}

// RequireKey accepts a request only with a valid key in X-API-Key that
// grants every one of scopes, and puts the key into the request context
// (FromContext). It answers with JSON errors:
//
//   - 401: no key, a malformed, unknown or revoked key;
//   - 403: a browser key from an origin it does not allow, a server key
//     sent from a browser (an Origin header), a client address outside the
//     key's networks, a missing scope;
//   - 503: the dashboard cannot be asked.
//
// A browser key's allowed origin is echoed in Access-Control-Allow-Origin,
// so the page can read the answer. The client address is RemoteAddr: put
// fullstack's web.TrustProxy (HTTP_TRUSTED_PROXIES) in front behind nginx.
func RequireKey(v Verifier, scopes ...Scope) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := strings.TrimSpace(r.Header.Get(Header))
			if raw == "" {
				deny(w, http.StatusUnauthorized, "missing API key (X-API-Key)")
				return
			}
			kind, err := KindOf(raw)
			if err != nil {
				deny(w, http.StatusUnauthorized, "invalid API key")
				return
			}
			k, err := v.Introspect(r.Context(), Hash(raw))
			if errors.Is(err, ErrUnknownKey) {
				deny(w, http.StatusUnauthorized, "invalid API key")
				return
			}
			if err != nil {
				deny(w, http.StatusServiceUnavailable, "API keys cannot be checked right now")
				return
			}
			if k.Kind != kind {
				deny(w, http.StatusUnauthorized, "invalid API key")
				return
			}
			origin := r.Header.Get("Origin")
			switch {
			case kind == Browser && !OriginAllowed(k, origin):
				deny(w, http.StatusForbidden, "origin not allowed for this key")
				return
			case kind == Server && origin != "":
				deny(w, http.StatusForbidden, "server keys must not be used from a browser; use a browser key")
				return
			}
			if !AddressAllowed(k, r.RemoteAddr) {
				deny(w, http.StatusForbidden, "client address not allowed for this key")
				return
			}
			if !k.Has(scopes...) {
				deny(w, http.StatusForbidden, "the key lacks a required scope")
				return
			}
			if kind == Browser {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Add("Vary", "Origin")
			}
			next.ServeHTTP(w, r.WithContext(WithKey(r.Context(), k)))
		})
	}
}

// OriginAllowed reports whether origin is one of the key's origins
// (scheme, host and port compared case-insensitively; a trailing slash
// ignored).
func OriginAllowed(k *Key, origin string) bool {
	o := normOrigin(origin)
	if o == "" || o == "null" {
		return false
	}
	return slices.ContainsFunc(k.Origins, func(a string) bool { return normOrigin(a) == o })
}

// AddressAllowed reports whether the request's RemoteAddr is in one of
// the key's networks; a key without networks allows every address.
func AddressAllowed(k *Key, remote string) bool {
	if len(k.IPs) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.WithZone("").Unmap()
	for _, s := range k.IPs {
		if p, err := ParseNetwork(s); err == nil && p.Contains(addr) {
			return true
		}
	}
	return false
}

// ParseNetwork reads an allowed network of a key: a CIDR or one address.
func ParseNetwork(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func normOrigin(s string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(s)), "/")
}

// CORS answers browsers' preflight requests for routes behind RequireKey:
// an OPTIONS request with Origin and Access-Control-Request-Method gets
// 204 allowing X-API-Key, Authorization and Content-Type. It allows every
// origin at this step because a preflight carries no key; the request that
// follows is checked by RequireKey, which sends Access-Control-Allow-Origin
// only for the key's own origins. No credentials (cookies) are allowed:
// Luna APIs use tokens.
func CORS(methods ...string) func(http.Handler) http.Handler {
	if len(methods) == 0 {
		methods = []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	}
	allow := strings.Join(methods, ", ")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if r.Method == http.MethodOptions && origin != "" && r.Header.Get("Access-Control-Request-Method") != "" {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Access-Control-Allow-Methods", allow)
				h.Set("Access-Control-Allow-Headers", Header+", Authorization, Content-Type")
				h.Set("Access-Control-Max-Age", "600")
				h.Add("Vary", "Origin")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func deny(w http.ResponseWriter, status int, msg string) { writeError(w, status, msg) }
