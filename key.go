package keys

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// Kind tells server keys from browser keys.
type Kind string

const (
	// Server keys are secret: they live in a client's backend and may hold
	// any scope. Prefix sk_live.
	Server Kind = "server"
	// Browser keys are public: they ship in a web page, are accepted only
	// from the application's allowed origins and hold AuthLogin only.
	// Prefix pk_live.
	Browser Kind = "browser"
)

// The key prefixes. A key is "<prefix>_" followed by 32 random bytes in
// unpadded base64url (43 characters), the format of passport-apikey.
const (
	ServerPrefix  = "sk_live"
	BrowserPrefix = "pk_live"
	secretLen     = 43
)

// Header is the request header a key travels in. Authorization stays free
// for the end user's token.
const Header = "X-API-Key"

// ErrMalformed is returned for a string that is not a Luna key.
var ErrMalformed = errors.New("keys: malformed API key")

// Generate makes a new key of the kind. Show key to the developer once;
// store only hash (Hash) and Hint(key).
func Generate(kind Kind) (key, hash string, err error) {
	prefix, ok := prefixOf(kind)
	if !ok {
		return "", "", errors.New("keys: unknown key kind " + string(kind))
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	key = prefix + "_" + base64.RawURLEncoding.EncodeToString(raw)
	return key, Hash(key), nil
}

// Hash is the hex SHA-256 of a key (as passport-apikey computes it): what
// the dashboard stores and what services send to it. A fast hash is right
// for 256 random bits, unlike for a password.
func Hash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// KindOf returns the kind of a well-formed key. The secret may itself
// contain "_" (it is base64url), so the key is split at the known prefix.
func KindOf(key string) (Kind, error) {
	for _, kind := range []Kind{Server, Browser} {
		prefix, _ := prefixOf(kind)
		if secret, ok := strings.CutPrefix(key, prefix+"_"); ok && len(secret) == secretLen && urlSafe(secret) {
			return kind, nil
		}
	}
	return "", ErrMalformed
}

// Hint is the part of a key that may be shown later to recognise it:
// "sk_live_…Q9xF", the prefix and the last 4 characters ("" for a
// malformed key).
func Hint(key string) string {
	kind, err := KindOf(key)
	if err != nil {
		return ""
	}
	prefix, _ := prefixOf(kind)
	return prefix + "_…" + key[len(key)-4:]
}

func prefixOf(kind Kind) (string, bool) {
	switch kind {
	case Server:
		return ServerPrefix, true
	case Browser:
		return BrowserPrefix, true
	}
	return "", false
}

func urlSafe(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
