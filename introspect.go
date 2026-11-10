package keys

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// IntrospectPath is where luna-dashboard answers introspection requests.
// It is internal: nginx never routes it.
const IntrospectPath = "/internal/v1/keys/introspect"

// ErrUnknownKey means the dashboard does not know the key, or it was
// revoked.
var ErrUnknownKey = errors.New("keys: unknown or revoked API key")

// Key is what the dashboard knows about a valid key.
type Key struct {
	ID      string   `json:"key_id"`
	AppID   string   `json:"app_id"`
	AppName string   `json:"app_name,omitempty"`
	Kind    Kind     `json:"kind"`
	Scopes  []Scope  `json:"scopes"`
	Origins []string `json:"origins,omitempty"` // allowed Origin values, e.g. https://app.example
	IPs     []string `json:"ips,omitempty"`     // allowed client networks (CIDRs or addresses); empty: any
}

// Has reports whether the key grants every scope.
func (k *Key) Has(scopes ...Scope) bool {
	for _, s := range scopes {
		if !slices.Contains(k.Scopes, s) {
			return false
		}
	}
	return true
}

// Verifier finds the key with a hash. Client is the network one; the
// dashboard can check its own keys directly.
type Verifier interface {
	// Introspect returns ErrUnknownKey for an unknown or revoked key and
	// other errors when it cannot tell.
	Introspect(ctx context.Context, hash string) (*Key, error)
}

// introspection is the wire format (RFC 7662 style: "active").
type introspection struct {
	Active bool `json:"active"`
	*Key
}

type introspectRequest struct {
	Hash string `json:"hash"`
}

// Client asks luna-dashboard about keys and keeps the answers for a while,
// so that a service does not call the dashboard on every request. A
// revoked key stops working within ValidTTL.
type Client struct {
	URL        string        // the dashboard's base URL, e.g. http://luna-dashboard:8080
	Token      string        // this service's token for the introspection endpoint
	HTTP       *http.Client  // default: 5 s timeout
	ValidTTL   time.Duration // how long a valid key is kept (default 60 s)
	InvalidTTL time.Duration // how long an unknown key is kept (default 10 s)
	MaxEntries int           // cache size (default 10 000); the oldest half goes when full

	mu    sync.Mutex
	cache map[string]cached
	now   func() time.Time
}

type cached struct {
	key     *Key // nil: unknown
	expires time.Time
	added   time.Time
}

// NewClient returns a Client with the defaults.
func NewClient(url, token string) *Client { return &Client{URL: url, Token: token} }

// Introspect implements Verifier.
func (c *Client) Introspect(ctx context.Context, hash string) (*Key, error) {
	now := c.clock()
	c.mu.Lock()
	if e, ok := c.cache[hash]; ok && now.Before(e.expires) {
		c.mu.Unlock()
		if e.key == nil {
			return nil, ErrUnknownKey
		}
		return e.key, nil
	}
	c.mu.Unlock()

	k, err := c.fetch(ctx, hash)
	if err != nil && !errors.Is(err, ErrUnknownKey) {
		return nil, err // not cached: the next request asks again
	}
	ttl := orDefault(c.ValidTTL, time.Minute)
	if k == nil {
		ttl = orDefault(c.InvalidTTL, 10*time.Second)
	}
	c.mu.Lock()
	c.store(hash, cached{key: k, expires: now.Add(ttl), added: now})
	c.mu.Unlock()
	if k == nil {
		return nil, ErrUnknownKey
	}
	return k, nil
}

// Forget drops a hash from the cache (all hashes when hash is "").
func (c *Client) Forget(hash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if hash == "" {
		c.cache = nil
		return
	}
	delete(c.cache, hash)
}

func (c *Client) store(hash string, e cached) {
	if c.cache == nil {
		c.cache = map[string]cached{}
	}
	limit := c.MaxEntries
	if limit <= 0 {
		limit = 10000
	}
	if len(c.cache) >= limit {
		// drop the expired entries and the older half of the rest
		var ages []time.Time
		for h, x := range c.cache {
			if !e.added.Before(x.expires) {
				delete(c.cache, h)
				continue
			}
			ages = append(ages, x.added)
		}
		if len(c.cache) >= limit {
			slices.SortFunc(ages, func(a, b time.Time) int { return a.Compare(b) })
			cut := ages[len(ages)/2]
			for h, x := range c.cache {
				if x.added.Before(cut) || x.added.Equal(cut) {
					delete(c.cache, h)
				}
			}
		}
	}
	c.cache[hash] = e
}

func (c *Client) fetch(ctx context.Context, hash string) (*Key, error) {
	body, _ := json.Marshal(introspectRequest{Hash: hash})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.URL, "/")+IntrospectPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keys: introspection: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("keys: introspection: dashboard answered %s", resp.Status)
	}
	var out introspection
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("keys: introspection: %w", err)
	}
	if !out.Active || out.Key == nil {
		return nil, ErrUnknownKey
	}
	return out.Key, nil
}

func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// LookupFunc finds a key by its hash in the dashboard's database: (nil,
// nil) or ErrUnknownKey when there is no such key or it is revoked.
type LookupFunc func(ctx context.Context, hash string) (*Key, error)

// Handler is the dashboard's side of the protocol: mount it at
// IntrospectPath on the internal network only. Callers authenticate with
// one of tokens (one per service, compared in constant time).
func Handler(lookup LookupFunc, tokens ...string) http.Handler {
	valid := slices.DeleteFunc(slices.Clone(tokens), func(t string) bool { return t == "" })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !tokenOK(r, valid) {
			writeError(w, http.StatusUnauthorized, "invalid service token")
			return
		}
		var in introspectRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil || len(in.Hash) != 64 {
			writeError(w, http.StatusBadRequest, "expected {\"hash\": \"<hex sha-256>\"}")
			return
		}
		k, err := lookup(r.Context(), strings.ToLower(in.Hash))
		if errors.Is(err, ErrUnknownKey) || (err == nil && k == nil) {
			writeJSON(w, http.StatusOK, introspection{Active: false})
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "lookup failed")
			return
		}
		writeJSON(w, http.StatusOK, introspection{Active: true, Key: k})
	})
}

func tokenOK(r *http.Request, valid []string) bool {
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" {
		return false
	}
	match := 0
	for _, v := range valid {
		match |= subtle.ConstantTimeCompare([]byte(tok), []byte(v))
	}
	return match == 1
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
