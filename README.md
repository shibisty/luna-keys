# luna-keys

The shared definition of a Luna API key, used by every Luna service:

- **Scopes**: `auth:login`, `auth:users.read`, `auth:users.write`, `pages:read`, `pages:write`
  (`keys.Scopes()` is the catalogue for forms; `ParseScopes`, `CheckScopes`).
- **Key format**: `sk_live_…` server keys (secret, any scope) and `pk_live_…` browser keys
  (public, allowed origins only, `auth:login` only) — the prefix, `_` and 32 random bytes in
  unpadded base64url, as passport-apikey makes them. Only the hex SHA-256 (`keys.Hash`) is
  stored; `keys.Hint` is what may be shown later (`sk_live_…Q9xF`).
- **Introspection**: luna-dashboard mounts `keys.Handler(lookup, serviceTokens...)` at
  `keys.IntrospectPath` (`/internal/v1/keys/introspect`, internal network only); services ask it
  with `keys.NewClient(url, token)`, which sends the key's hash (never the key) and keeps answers
  for 60 s (unknown keys 10 s), so a revoked key stops working within a minute.
- **Middleware**: `keys.RequireKey(verifier, scopes...)` accepts a request with a valid key in
  `X-API-Key` (the `Authorization` header stays free for the end user's token), checks the kind
  (a server key sent with an `Origin` is refused), the allowed origins and networks, and the
  scopes, and puts the key into the context (`keys.FromContext`). `keys.CORS()` answers
  preflights. Behind nginx, put fullstack's `web.TrustProxy` (`HTTP_TRUSTED_PROXIES`) in front, so
  network allow-lists see the client.

Standard library only; Go 1.22+.

```go
v := keys.NewClient("http://luna-dashboard:8080", os.Getenv("LUNA_DASHBOARD_TOKEN"))
r.Group("/v1", func(r *web.Router) {
    r.Use(keys.CORS())
    r.Post("/sessions", login, keys.RequireKey(v, keys.AuthLogin))
})
```

```bash
gtr run test -- -race
```

## License

MIT
