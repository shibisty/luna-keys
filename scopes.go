// Package keys is the shared definition of a Luna API key: its scopes, its
// format, the introspection protocol between luna-dashboard (which issues
// keys) and the other Luna services (which check them), and the RequireKey
// middleware those services put in front of their routes.
//
// A key never travels between services: a service hashes the key it
// received (SHA-256, as passport-apikey stores it) and asks the dashboard
// about the hash.
package keys

import (
	"fmt"
	"slices"
	"strings"
)

// Scope is a permission a key grants, "<service>:<action>".
type Scope string

// The scopes of Luna services.
const (
	// AuthLogin lets a client register, log in and log out end users and
	// reset their passwords. It is the only scope a browser key may hold.
	AuthLogin Scope = "auth:login"
	// AuthUsersRead lets a server list and read the application's users.
	AuthUsersRead Scope = "auth:users.read"
	// AuthUsersWrite lets a server change and delete the application's users.
	AuthUsersWrite Scope = "auth:users.write"
	// PagesRead lets a client read the application's pages.
	PagesRead Scope = "pages:read"
	// PagesWrite lets a server create, change and delete pages.
	PagesWrite Scope = "pages:write"
)

// ScopeInfo describes a scope for the dashboard's forms.
type ScopeInfo struct {
	Scope       Scope
	Service     string // auth, pages
	Description string
	Browser     bool // may be held by a browser key
}

var catalogue = []ScopeInfo{
	{AuthLogin, "auth", "Register, log in and log out users, reset passwords", true},
	{AuthUsersRead, "auth", "List and read users", false},
	{AuthUsersWrite, "auth", "Change and delete users", false},
	{PagesRead, "pages", "Read pages", false},
	{PagesWrite, "pages", "Create, change and delete pages", false},
}

// Scopes is the catalogue of every scope, in display order.
func Scopes() []ScopeInfo { return slices.Clone(catalogue) }

// Lookup returns a scope's description.
func Lookup(s Scope) (ScopeInfo, bool) {
	for _, info := range catalogue {
		if info.Scope == s {
			return info, true
		}
	}
	return ScopeInfo{}, false
}

// ParseScopes reads scopes from strings (a form, a database column),
// rejecting unknown ones and dropping duplicates; the order is kept.
func ParseScopes(values []string) ([]Scope, error) {
	var out []Scope
	var unknown []string
	for _, v := range values {
		s := Scope(strings.TrimSpace(v))
		if _, ok := Lookup(s); !ok {
			unknown = append(unknown, v)
			continue
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("keys: unknown scopes %q", unknown)
	}
	return out, nil
}

// CheckScopes reports whether a key of the kind may hold the scopes: a
// browser key only scopes marked Browser, a server key any known scope.
func CheckScopes(kind Kind, scopes []Scope) error {
	if len(scopes) == 0 {
		return fmt.Errorf("keys: a key needs at least one scope")
	}
	for _, s := range scopes {
		info, ok := Lookup(s)
		if !ok {
			return fmt.Errorf("keys: unknown scope %q", s)
		}
		if kind == Browser && !info.Browser {
			return fmt.Errorf("keys: a browser key cannot hold %q", s)
		}
	}
	return nil
}
