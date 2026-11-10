package keys

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGenerateAndKindOf(t *testing.T) {
	underscore := 0
	for i := 0; i < 2000; i++ {
		for _, kind := range []Kind{Server, Browser} {
			key, hash, err := Generate(kind)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(key[len("sk_live_"):], "_") {
				underscore++
			}
			got, err := KindOf(key)
			if err != nil || got != kind {
				t.Fatalf("KindOf(%q) = %q, %v; want %q", key, got, err, kind)
			}
			if hash != Hash(key) || len(hash) != 64 {
				t.Fatalf("hash %q", hash)
			}
		}
	}
	if underscore == 0 {
		t.Fatal("no generated secret contained _; the test does not cover that case")
	}
	if _, _, err := Generate("admin"); err == nil {
		t.Fatal("unknown kind accepted")
	}
	for _, bad := range []string{"", "sk_live_", "sk_live_short", "xx_live_" + strings.Repeat("a", 43),
		"sk_live_" + strings.Repeat("a", 42) + "!", "sk_live_" + strings.Repeat("a", 44), strings.Repeat("a", 43)} {
		if _, err := KindOf(bad); !errors.Is(err, ErrMalformed) {
			t.Errorf("KindOf(%q) accepted", bad)
		}
	}
}

func TestHint(t *testing.T) {
	key := "pk_live_" + strings.Repeat("a", 39) + "Q9_F"
	if got := Hint(key); got != "pk_live_…Q9_F" {
		t.Fatalf("Hint = %q", got)
	}
	if Hint("nope") != "" {
		t.Fatal("hint for a malformed key")
	}
}

func TestScopes(t *testing.T) {
	got, err := ParseScopes([]string{"auth:login", " pages:read", "auth:login"})
	if err != nil || len(got) != 2 || got[0] != AuthLogin || got[1] != PagesRead {
		t.Fatalf("ParseScopes = %v, %v", got, err)
	}
	if _, err := ParseScopes([]string{"auth:login", "root"}); err == nil {
		t.Fatal("unknown scope accepted")
	}
	if err := CheckScopes(Browser, []Scope{AuthLogin}); err != nil {
		t.Fatal(err)
	}
	if err := CheckScopes(Browser, []Scope{AuthLogin, AuthUsersRead}); err == nil {
		t.Fatal("browser key with a server scope")
	}
	if err := CheckScopes(Server, []Scope{AuthUsersWrite, PagesWrite}); err != nil {
		t.Fatal(err)
	}
	if err := CheckScopes(Server, nil); err == nil {
		t.Fatal("key without scopes")
	}
	if len(Scopes()) != 7 {
		t.Fatalf("catalogue: %v", Scopes())
	}
}

// dashboard is a fake luna-dashboard: Handler over a map of keys.
type dashboard struct {
	srv   *httptest.Server
	calls atomic.Int64
	keys  map[string]*Key // by hash
	fail  atomic.Bool
}

func newDashboard(t *testing.T) *dashboard {
	d := &dashboard{keys: map[string]*Key{}}
	h := Handler(func(_ context.Context, hash string) (*Key, error) {
		d.calls.Add(1)
		if d.fail.Load() {
			return nil, errors.New("database down")
		}
		return d.keys[hash], nil
	}, "auth-token", "pages-token")
	d.srv = httptest.NewServer(h)
	t.Cleanup(d.srv.Close)
	return d
}

func (d *dashboard) add(t *testing.T, k *Key) string {
	key, hash, err := Generate(k.Kind)
	if err != nil {
		t.Fatal(err)
	}
	d.keys[hash] = k
	return key
}

func TestHandler(t *testing.T) {
	d := newDashboard(t)
	key := d.add(t, &Key{ID: "k1", AppID: "a1", Kind: Server, Scopes: []Scope{AuthLogin}})
	post := func(token, body string) (int, map[string]any) {
		req, _ := http.NewRequest("POST", d.srv.URL+IntrospectPath, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	if code, _ := post("", `{"hash":"`+Hash(key)+`"}`); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := post("wrong", `{"hash":"`+Hash(key)+`"}`); code != 401 {
		t.Fatalf("wrong token: %d", code)
	}
	if code, _ := post("auth-token", `{"hash":"short"}`); code != 400 {
		t.Fatalf("bad body: %d", code)
	}
	code, out := post("pages-token", `{"hash":"`+strings.ToUpper(Hash(key))+`"}`)
	if code != 200 || out["active"] != true || out["app_id"] != "a1" {
		t.Fatalf("known key: %d %v", code, out)
	}
	code, out = post("auth-token", `{"hash":"`+Hash("sk_live_"+strings.Repeat("x", 43))+`"}`)
	if code != 200 || out["active"] != false || out["app_id"] != nil {
		t.Fatalf("unknown key: %d %v", code, out)
	}
	d.fail.Store(true)
	if code, _ := post("auth-token", `{"hash":"`+Hash(key)+`"}`); code != 500 {
		t.Fatalf("lookup error: %d", code)
	}
	resp, _ := http.Get(d.srv.URL + IntrospectPath)
	if resp.StatusCode != 405 {
		t.Fatalf("GET: %d", resp.StatusCode)
	}
}

func TestClientCache(t *testing.T) {
	d := newDashboard(t)
	key := d.add(t, &Key{ID: "k1", AppID: "a1", Kind: Server, Scopes: []Scope{AuthLogin}})
	now := time.Unix(1_800_000_000, 0)
	c := NewClient(d.srv.URL+"/", "auth-token")
	c.now = func() time.Time { return now }
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		k, err := c.Introspect(ctx, Hash(key))
		if err != nil || k.AppID != "a1" {
			t.Fatalf("Introspect: %v %v", k, err)
		}
	}
	if n := d.calls.Load(); n != 1 {
		t.Fatalf("valid key asked %d times within its TTL", n)
	}
	unknown := Hash("sk_live_" + strings.Repeat("u", 43))
	for i := 0; i < 3; i++ {
		if _, err := c.Introspect(ctx, unknown); !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("unknown key: %v", err)
		}
	}
	if n := d.calls.Load(); n != 2 {
		t.Fatalf("unknown key asked %d times", n-1)
	}
	// revocation is seen after ValidTTL
	delete(d.keys, Hash(key))
	now = now.Add(59 * time.Second)
	if _, err := c.Introspect(ctx, Hash(key)); err != nil {
		t.Fatalf("still cached: %v", err)
	}
	now = now.Add(2 * time.Second)
	if _, err := c.Introspect(ctx, Hash(key)); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("revoked key after the TTL: %v", err)
	}
	// errors are not cached
	d.fail.Store(true)
	now = now.Add(time.Hour)
	if _, err := c.Introspect(ctx, unknown); err == nil || errors.Is(err, ErrUnknownKey) {
		t.Fatalf("dashboard failure: %v", err)
	}
	d.fail.Store(false)
	if _, err := c.Introspect(ctx, unknown); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("after recovery: %v", err)
	}
	bad := NewClient(d.srv.URL, "wrong")
	if _, err := bad.Introspect(ctx, Hash(key)); err == nil || errors.Is(err, ErrUnknownKey) {
		t.Fatalf("wrong service token: %v", err)
	}
	c.Forget("")
	if len(c.cache) != 0 {
		t.Fatal("Forget all")
	}
}

func TestClientEviction(t *testing.T) {
	d := newDashboard(t)
	now := time.Unix(1_800_000_000, 0)
	c := NewClient(d.srv.URL, "auth-token")
	c.MaxEntries = 10
	c.now = func() time.Time { return now }
	for i := 0; i < 25; i++ {
		now = now.Add(time.Millisecond)
		c.Introspect(context.Background(), Hash(strings.Repeat("k", i+1)))
		if len(c.cache) > 10 {
			t.Fatalf("cache grew to %d", len(c.cache))
		}
	}
}

// stub is a Verifier over a fixed key.
type stub struct {
	k   *Key
	err error
}

func (s stub) Introspect(context.Context, string) (*Key, error) { return s.k, s.err }

func TestRequireKey(t *testing.T) {
	serverKey, _, _ := Generate(Server)
	browserKey, _, _ := Generate(Browser)
	server := &Key{ID: "s", AppID: "app", Kind: Server, Scopes: []Scope{AuthLogin, AuthUsersRead}, IPs: []string{"203.0.113.0/24", "2001:db8::1"}}
	browser := &Key{ID: "b", AppID: "app", Kind: Browser, Scopes: []Scope{AuthLogin}, Origins: []string{"https://App.example/"}}

	cases := []struct {
		name   string
		v      Verifier
		scopes []Scope
		key    string
		origin string
		remote string
		want   int
		acao   string
	}{
		{"no key", stub{k: server}, nil, "", "", "203.0.113.5:1", 401, ""},
		{"malformed", stub{k: server}, nil, "sk_live_x", "", "203.0.113.5:1", 401, ""},
		{"unknown", stub{err: ErrUnknownKey}, nil, serverKey, "", "203.0.113.5:1", 401, ""},
		{"dashboard down", stub{err: errors.New("timeout")}, nil, serverKey, "", "203.0.113.5:1", 503, ""},
		{"kind mismatch", stub{k: browser}, nil, serverKey, "", "203.0.113.5:1", 401, ""},
		{"server key ok", stub{k: server}, []Scope{AuthUsersRead}, serverKey, "", "203.0.113.5:1", 200, ""},
		{"server key, IPv6 address", stub{k: server}, nil, serverKey, "", "[2001:db8::1]:443", 200, ""},
		{"server key from a browser", stub{k: server}, nil, serverKey, "https://app.example", "203.0.113.5:1", 403, ""},
		{"server key, address not allowed", stub{k: server}, nil, serverKey, "", "198.51.100.1:1", 403, ""},
		{"missing scope", stub{k: server}, []Scope{AuthUsersWrite}, serverKey, "", "203.0.113.5:1", 403, ""},
		{"browser key ok", stub{k: browser}, []Scope{AuthLogin}, browserKey, "https://app.example", "198.51.100.1:1", 200, "https://app.example"},
		{"browser key, other origin", stub{k: browser}, nil, browserKey, "https://evil.example", "198.51.100.1:1", 403, ""},
		{"browser key, no origin", stub{k: browser}, nil, browserKey, "", "198.51.100.1:1", 403, ""},
		{"browser key, null origin", stub{k: browser}, nil, browserKey, "null", "198.51.100.1:1", 403, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var seen *Key
			h := RequireKey(c.v, c.scopes...)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen, _ = FromContext(r.Context())
				w.WriteHeader(200)
			}))
			req := httptest.NewRequest("POST", "/v1/sessions", nil)
			req.RemoteAddr = c.remote
			if c.key != "" {
				req.Header.Set(Header, c.key)
			}
			if c.origin != "" {
				req.Header.Set("Origin", c.origin)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != c.want {
				t.Fatalf("status %d, want %d: %s", w.Code, c.want, w.Body)
			}
			if got := w.Header().Get("Access-Control-Allow-Origin"); got != c.acao {
				t.Fatalf("Access-Control-Allow-Origin %q, want %q", got, c.acao)
			}
			if c.want == 200 && seen == nil {
				t.Fatal("key not in the context")
			}
			if c.want != 200 && !strings.Contains(w.Header().Get("Content-Type"), "json") {
				t.Fatal("error is not JSON")
			}
		})
	}
}

func TestCORS(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) })
	h := CORS()(next)
	req := httptest.NewRequest("OPTIONS", "/v1/sessions", nil)
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != "https://app.example" ||
		!strings.Contains(w.Header().Get("Access-Control-Allow-Headers"), "X-API-Key") ||
		w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("preflight: %d %v", w.Code, w.Header())
	}
	plain := httptest.NewRequest("OPTIONS", "/v1/sessions", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, plain)
	if w.Code != 299 {
		t.Fatalf("OPTIONS without preflight headers was answered: %d", w.Code)
	}
}

func TestParseNetwork(t *testing.T) {
	for in, want := range map[string]string{"10.1.2.3": "10.1.2.3/32", "10.1.2.3/8": "10.0.0.0/8", "::ffff:1.2.3.4": "1.2.3.4/32", " 2001:db8::/32 ": "2001:db8::/32"} {
		p, err := ParseNetwork(in)
		if err != nil || p.String() != want {
			t.Errorf("ParseNetwork(%q) = %v, %v; want %s", in, p, err, want)
		}
	}
	if _, err := ParseNetwork("nope"); err == nil {
		t.Error("bad network accepted")
	}
	if AddressAllowed(&Key{IPs: []string{"10.0.0.0/8"}}, "garbage") {
		t.Error("garbage address allowed")
	}
}
