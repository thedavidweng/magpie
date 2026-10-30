package provider

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func isolateAntigravity(t *testing.T) (*fakeKeychain, string) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	fk := &fakeKeychain{service: antigravityKeychainService, items: map[string][]byte{}}
	oldKeychain, oldHere := antigravityKeychain, antigravityKeychainHere
	antigravityKeychain, antigravityKeychainHere = fk, true
	t.Cleanup(func() {
		antigravityKeychain, antigravityKeychainHere = oldKeychain, oldHere
	})
	return fk, tmp
}

func sampleAntigravityAuth(email string) []byte {
	p := antigravityPayload{
		Token: antigravityToken{
			AccessToken:  "ya29.sample-token-123",
			TokenType:    "Bearer",
			RefreshToken: "1//sample-refresh-456",
			Expiry:       "2026-10-30T12:00:00Z",
			ExpiresIn:    3600,
		},
		AuthMethod:   "consumer",
		IDTokenEmail: email,
	}
	b, _ := json.Marshal(p)
	return b
}

func TestAntigravityStoreRoundtripKeychain(t *testing.T) {
	fk, tmp := isolateAntigravity(t)

	want := savedLogin{
		Agent: "antigravity",
		User:  "developer@example.com",
		Auth:  sampleAntigravityAuth("developer@example.com"),
	}

	if err := saveAntigravityLogin(want); err != nil {
		t.Fatalf("saveAntigravityLogin: %v", err)
	}

	// Verify Keychain item
	secret, ok := fk.items[antigravityKeychainAccount]
	if !ok {
		t.Fatalf("keychain item %q not found", antigravityKeychainAccount)
	}
	if !strings.HasPrefix(string(secret), antigravityKeyringPrefix) {
		t.Fatalf("keychain secret missing prefix: %s", string(secret))
	}

	// Verify disk dual-write
	cliToken := filepath.Join(tmp, ".gemini", "antigravity-cli", "antigravity-oauth-token")
	if _, err := os.Stat(cliToken); err != nil {
		t.Fatalf("cli token file missing: %v", err)
	}
	jetskiToken := filepath.Join(tmp, ".gemini", "jetski-standalone-oauth-token")
	if _, err := os.Stat(jetskiToken); err != nil {
		t.Fatalf("jetski token file missing: %v", err)
	}
	googleAccts := filepath.Join(tmp, ".gemini", "google_accounts.json")
	b, err := os.ReadFile(googleAccts)
	if err != nil {
		t.Fatalf("reading google_accounts.json: %v", err)
	}
	if !strings.Contains(string(b), "developer@example.com") {
		t.Fatalf("google_accounts.json missing active account: %s", string(b))
	}

	// Read back
	got, ok, err := readAntigravityLogin()
	if err != nil {
		t.Fatalf("readAntigravityLogin: %v", err)
	}
	if !ok {
		t.Fatal("readAntigravityLogin returned ok=false")
	}
	if got.User != want.User {
		t.Fatalf("User mismatch: got %q, want %q", got.User, want.User)
	}
	if got.Agent != "antigravity" {
		t.Fatalf("Agent mismatch: got %q, want %q", got.Agent, "antigravity")
	}

	// Live login
	live, liveOk := antigravityLiveLogin()
	if !liveOk || live.User != want.User {
		t.Fatalf("antigravityLiveLogin failed: got %v, ok %v", live, liveOk)
	}
}

func TestAntigravityStoreRoundtripFileFallback(t *testing.T) {
	_, tmp := isolateAntigravity(t)
	// Disable keychain to force file fallback
	antigravityKeychainHere = false

	want := savedLogin{
		Agent: "antigravity",
		User:  "fallback@example.com",
		Auth:  sampleAntigravityAuth("fallback@example.com"),
	}

	if err := saveAntigravityLogin(want); err != nil {
		t.Fatalf("saveAntigravityLogin: %v", err)
	}

	// Ensure keychain was NOT written
	cliToken := filepath.Join(tmp, ".gemini", "antigravity-cli", "antigravity-oauth-token")
	if _, err := os.Stat(cliToken); err != nil {
		t.Fatalf("cli token file missing: %v", err)
	}

	got, ok, err := readAntigravityLogin()
	if err != nil {
		t.Fatalf("readAntigravityLogin: %v", err)
	}
	if !ok {
		t.Fatal("readAntigravityLogin returned ok=false")
	}
	if got.User != want.User {
		t.Fatalf("User mismatch: got %q, want %q", got.User, want.User)
	}
}

func TestAntigravityStoreCorruptKeychain(t *testing.T) {
	fk, _ := isolateAntigravity(t)

	// Missing prefix
	fk.items[antigravityKeychainAccount] = []byte("not-base64-payload")
	if _, _, err := readAntigravityLogin(); err == nil {
		t.Fatal("expected error on missing keychain prefix, got nil")
	}

	// Corrupt base64
	fk.items[antigravityKeychainAccount] = []byte(antigravityKeyringPrefix + "!!!invalid-b64")
	if _, _, err := readAntigravityLogin(); err == nil {
		t.Fatal("expected error on invalid base64, got nil")
	}

	// Corrupt JSON payload
	fk.items[antigravityKeychainAccount] = []byte(antigravityKeyringPrefix + base64.StdEncoding.EncodeToString([]byte("not json")))
	if _, _, err := readAntigravityLogin(); err == nil {
		t.Fatal("expected error on invalid JSON payload, got nil")
	}

	// Empty token fields
	fk.items[antigravityKeychainAccount] = []byte(antigravityKeyringPrefix + base64.StdEncoding.EncodeToString([]byte(`{"token":{}}`)))
	if _, _, err := readAntigravityLogin(); err == nil {
		t.Fatal("expected error on missing token fields, got nil")
	}

	if _, ok := antigravityLiveLogin(); ok {
		t.Fatal("expected antigravityLiveLogin to return false on corrupt keychain")
	}
}

func TestAntigravityStoreCorruptFile(t *testing.T) {
	_, tmp := isolateAntigravity(t)
	antigravityKeychainHere = false

	cliToken := filepath.Join(tmp, ".gemini", "antigravity-cli", "antigravity-oauth-token")
	if err := os.MkdirAll(filepath.Dir(cliToken), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cliToken, []byte("broken json"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := readAntigravityLogin(); err == nil {
		t.Fatal("expected error on broken token file, got nil")
	}
}

func TestAntigravityStoreEmptyLogin(t *testing.T) {
	isolateAntigravity(t)

	if err := saveAntigravityLogin(savedLogin{Agent: "antigravity"}); err == nil {
		t.Fatal("expected error on empty login, got nil")
	}

	if err := saveAntigravityLogin(savedLogin{Agent: "antigravity", Auth: []byte("invalid json")}); err == nil {
		t.Fatal("expected error on invalid json, got nil")
	}
}

func TestAntigravitySwitchIntegration(t *testing.T) {
	_, tmp := isolateAntigravity(t)

	auth1 := sampleAntigravityAuth("user1@example.com")
	auth2 := sampleAntigravityAuth("user2@example.com")

	// Set initial live account to user1
	if err := saveAntigravityLogin(savedLogin{
		Agent: "antigravity",
		User:  "user1@example.com",
		Auth:  auth1,
	}); err != nil {
		t.Fatalf("saving initial login: %v", err)
	}

	// Save user1 and user2 in logins.json
	ls := []savedLogin{
		{Agent: "antigravity", User: "user1@example.com", Auth: auth1},
		{Agent: "antigravity", User: "user2@example.com", Auth: auth2},
	}
	loginsMu.Lock()
	if err := writeLogins(ls); err != nil {
		loginsMu.Unlock()
		t.Fatalf("writing logins.json: %v", err)
	}
	loginsMu.Unlock()

	// Switch to user2
	if err := switchLogin("antigravity", "user2@example.com"); err != nil {
		t.Fatalf("switchLogin to user2: %v", err)
	}

	// Verify active account is now user2
	live, ok := antigravityLiveLogin()
	if !ok || live.User != "user2@example.com" {
		t.Fatalf("live login after switch: got %v, ok %v", live, ok)
	}

	// Verify google_accounts.json updated
	b, err := os.ReadFile(filepath.Join(tmp, ".gemini", "google_accounts.json"))
	if err != nil {
		t.Fatalf("reading google_accounts.json: %v", err)
	}
	if !strings.Contains(string(b), "user2@example.com") {
		t.Fatalf("expected active user2@example.com in google_accounts.json: %s", string(b))
	}
}
