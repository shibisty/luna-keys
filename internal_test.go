package keys

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInternal(t *testing.T) {
	mux := http.NewServeMux()
	var got *Key
	h := Internal("secret", PagesRead, PagesWrite)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = FromContext(r.Context())
	}))
	mux.Handle("/internal/v1/apps/{app}/x", h)
	app := "0b6f2b1e-6f0a-4a43-9b2e-6f0c5c1d2e3f"
	call := func(path, auth string) int {
		req := httptest.NewRequest("GET", path, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := call("/internal/v1/apps/"+app+"/x", ""); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code := call("/internal/v1/apps/"+app+"/x", "Bearer wrong"); code != 401 {
		t.Fatalf("wrong token: %d", code)
	}
	if code := call("/internal/v1/apps/not-a-uuid/x", "Bearer secret"); code != 404 {
		t.Fatalf("bad app: %d", code)
	}
	if code := call("/internal/v1/apps/"+app+"/x", "bearer secret"); code != 200 || got == nil {
		t.Fatalf("ok: %d %v", code, got)
	}
	if got.AppID != app || got.Kind != Server || !got.Has(PagesWrite) || got.Has(AuthLogin) {
		t.Fatalf("key: %+v", got)
	}
	if Internal("")(http.NotFoundHandler()) == nil {
		t.Fatal("nil handler")
	}
	empty := Internal("")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("empty token let a request in") }))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer ")
	empty.ServeHTTP(httptest.NewRecorder(), req)
}

func TestUUIDLike(t *testing.T) {
	for s, want := range map[string]bool{
		"0b6f2b1e-6f0a-4a43-9b2e-6f0c5c1d2e3f": true,
		"0B6F2B1E-6F0A-4A43-9B2E-6F0C5C1D2E3F": false,
		"0b6f2b1e6f0a4a439b2e6f0c5c1d2e3f":     false,
		"0b6f2b1e-6f0a-4a43-9b2e-6f0c5c1d2e3g": false,
	} {
		if UUIDLike(s) != want {
			t.Errorf("%s: %v", s, !want)
		}
	}
}
