package provider

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func isolateFactory(t *testing.T) (*fakeKeychain, string) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	fk := &fakeKeychain{service: factoryKeychainService, items: map[string][]byte{}}
	oldKeychain, oldHere := factoryKeychain, factoryKeychainHere
	factoryKeychain, factoryKeychainHere = fk, true
	t.Cleanup(func() {
		factoryKeychain, factoryKeychainHere = oldKeychain, oldHere
	})
	return fk, tmp
}

func sampleFactoryAuth(email, org string) []byte {
	m := map[string]any{
		"access_token":           "fact_acc_1234567890",
		"refresh_token":          "fact_ref_0987654321",
		"active_organization_id": org,
		"email":                  email,
		"whoami": map[string]any{
			"email":           email,
			"userId":          "usr_abc123",
			"inferenceRegion": "us",
			"isEnterprise":    false,
		},
	}
	b, _ := json.Marshal(m)
	return b
}

func TestFactoryVaultEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"access_token":"secret-token","email":"test@factory.ai"}`)

	vault, err := encryptFactoryVault(key, payload)
	if err != nil {
		t.Fatalf("encryptFactoryVault: %v", err)
	}

	parts := strings.Split(vault, ":")
	if len(parts) != 3 {
		t.Fatalf("expected 3 colon-separated parts, got %d (%s)", len(parts), vault)
	}

	decrypted, err := decryptFactoryVault(key, vault)
	if err != nil {
		t.Fatalf("decryptFactoryVault: %v", err)
	}

	if string(decrypted) != string(payload) {
		t.Fatalf("decrypted mismatch: got %s, want %s", string(decrypted), string(payload))
	}

	// Test invalid key length
	if _, err := encryptFactoryVault([]byte("too-short"), payload); err == nil {
		t.Fatal("expected error on short key in encrypt, got nil")
	}
	if _, err := decryptFactoryVault([]byte("too-short"), vault); err == nil {
		t.Fatal("expected error on short key in decrypt, got nil")
	}

	// Test wrong key
	wrongKey := make([]byte, 32)
	wrongKey[0] = ^key[0]
	if _, err := decryptFactoryVault(wrongKey, vault); err == nil {
		t.Fatal("expected error with wrong key, got nil")
	}

	// Test corrupted components
	if _, err := decryptFactoryVault(key, "invalid:vault"); err == nil {
		t.Fatal("expected error on invalid parts count")
	}
	if _, err := decryptFactoryVault(key, "bad-b64:bad-tag:bad-ct"); err == nil {
		t.Fatal("expected error on bad base64")
	}
}

func TestFactoryStoreRoundtripKeychain(t *testing.T) {
	fk, tmp := isolateFactory(t)

	want := savedLogin{
		Agent: "factory",
		User:  "engineer@factory.ai",
		Auth:  sampleFactoryAuth("engineer@factory.ai", "org_test1"),
	}

	if err := saveFactoryLogin(want); err != nil {
		t.Fatalf("saveFactoryLogin: %v", err)
	}

	// Verify Keychain item
	keyB64, ok := fk.items[factoryKeychainAccount]
	if !ok {
		t.Fatalf("keychain item %q not found", factoryKeychainAccount)
	}
	rawKey, decErr := base64.StdEncoding.DecodeString(string(keyB64))
	if decErr != nil || len(rawKey) != 32 {
		t.Fatalf("invalid key in keychain: %v (len %d)", decErr, len(rawKey))
	}

	// Verify disk files
	keyFile := filepath.Join(tmp, ".factory", "auth.v2.key")
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatalf("auth.v2.key missing: %v", err)
	}
	fileVault := filepath.Join(tmp, ".factory", "auth.v2.file")
	if _, err := os.Stat(fileVault); err != nil {
		t.Fatalf("auth.v2.file missing: %v", err)
	}
	keychainVault := filepath.Join(tmp, ".factory", "auth.v2.loginkeychain")
	if _, err := os.Stat(keychainVault); err != nil {
		t.Fatalf("auth.v2.loginkeychain missing: %v", err)
	}

	// Read back
	got, ok, err := readFactoryLogin()
	if err != nil {
		t.Fatalf("readFactoryLogin: %v", err)
	}
	if !ok {
		t.Fatal("readFactoryLogin returned ok=false")
	}
	if got.User != want.User {
		t.Fatalf("User mismatch: got %q, want %q", got.User, want.User)
	}
	if got.Agent != "factory" {
		t.Fatalf("Agent mismatch: got %q, want %q", got.Agent, "factory")
	}

	// Live login
	live, liveOk := factoryLiveLogin()
	if !liveOk || live.User != want.User {
		t.Fatalf("factoryLiveLogin failed: got %v, ok %v", live, liveOk)
	}
}

func TestFactoryStoreRoundtripFileFallback(t *testing.T) {
	_, tmp := isolateFactory(t)
	factoryKeychainHere = false

	want := savedLogin{
		Agent: "factory",
		User:  "fallback@factory.ai",
		Auth:  sampleFactoryAuth("fallback@factory.ai", "org_test2"),
	}

	if err := saveFactoryLogin(want); err != nil {
		t.Fatalf("saveFactoryLogin: %v", err)
	}

	// Ensure auth.v2.file and key exist
	fileVault := filepath.Join(tmp, ".factory", "auth.v2.file")
	if _, err := os.Stat(fileVault); err != nil {
		t.Fatalf("auth.v2.file missing: %v", err)
	}

	got, ok, err := readFactoryLogin()
	if err != nil {
		t.Fatalf("readFactoryLogin: %v", err)
	}
	if !ok {
		t.Fatal("readFactoryLogin returned ok=false")
	}
	if got.User != want.User {
		t.Fatalf("User mismatch: got %q, want %q", got.User, want.User)
	}
}

func TestFactoryStoreCorruptVault(t *testing.T) {
	_, tmp := isolateFactory(t)
	factoryKeychainHere = false

	dir := filepath.Join(tmp, ".factory")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}

	key := make([]byte, 32)
	rand.Read(key)
	os.WriteFile(filepath.Join(dir, "auth.v2.key"), []byte(base64.StdEncoding.EncodeToString(key)), 0600)
	os.WriteFile(filepath.Join(dir, "auth.v2.file"), []byte("corrupt:vault:data"), 0600)

	if _, _, err := readFactoryLogin(); err == nil {
		t.Fatal("expected error on corrupt vault data, got nil")
	}

	// Corrupt key
	os.WriteFile(filepath.Join(dir, "auth.v2.key"), []byte("not-32-byte-key"), 0600)
	if _, _, err := readFactoryLogin(); err == nil {
		t.Fatal("expected error on corrupt key, got nil")
	}

	if _, ok := factoryLiveLogin(); ok {
		t.Fatal("expected factoryLiveLogin to return false on corrupt files")
	}
}

func TestFactoryStoreEmptyLogin(t *testing.T) {
	isolateFactory(t)

	if err := saveFactoryLogin(savedLogin{Agent: "factory"}); err == nil {
		t.Fatal("expected error on empty login, got nil")
	}

	if err := saveFactoryLogin(savedLogin{Agent: "factory", Auth: []byte("invalid json")}); err == nil {
		t.Fatal("expected error on invalid json, got nil")
	}
}

func TestFactorySwitchIntegration(t *testing.T) {
	_, _ = isolateFactory(t)

	auth1 := sampleFactoryAuth("user1@factory.ai", "org_1")
	auth2 := sampleFactoryAuth("user2@factory.ai", "org_2")

	// Set initial live account to user1
	if err := saveFactoryLogin(savedLogin{
		Agent: "factory",
		User:  "user1@factory.ai",
		Auth:  auth1,
	}); err != nil {
		t.Fatalf("saving initial login: %v", err)
	}

	// Save user1 and user2 in logins.json
	ls := []savedLogin{
		{Agent: "factory", User: "user1@factory.ai", Auth: auth1},
		{Agent: "factory", User: "user2@factory.ai", Auth: auth2},
	}
	loginsMu.Lock()
	if err := writeLogins(ls); err != nil {
		loginsMu.Unlock()
		t.Fatalf("writing logins.json: %v", err)
	}
	loginsMu.Unlock()

	// Switch to user2
	if err := switchLogin("factory", "user2@factory.ai"); err != nil {
		t.Fatalf("switchLogin to user2: %v", err)
	}

	// Verify active account is now user2
	live, ok := factoryLiveLogin()
	if !ok || live.User != "user2@factory.ai" {
		t.Fatalf("live login after switch: got %v, ok %v", live, ok)
	}
}

func TestRoutingSetSwitchOnly(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	// Save an antigravity login so Accounts() discovers it
	ls := []savedLogin{
		{
			Agent: "antigravity",
			User:  "developer@example.com",
			Auth:  []byte(`{"refresh_token":"sample-refresh-token"}`),
		},
	}
	loginsMu.Lock()
	if err := writeLogins(ls); err != nil {
		loginsMu.Unlock()
		t.Fatalf("writing logins.json: %v", err)
	}
	loginsMu.Unlock()

	// Switch-only on antigravity should succeed
	if err := SetSwitchOnly("antigravity", true); err != nil {
		t.Fatalf("SetSwitchOnly(antigravity): %v", err)
	}
	p, err := Find("antigravity")
	if err != nil || !p.SwitchOnly {
		t.Fatalf("Find(antigravity): %+v, err: %v", p, err)
	}

	// Disable switch-only
	if err := SetSwitchOnly("antigravity", false); err != nil {
		t.Fatalf("SetSwitchOnly(antigravity, false): %v", err)
	}
	p, err = Find("antigravity")
	if err != nil || p.SwitchOnly {
		t.Fatalf("expected SwitchOnly false: %+v, err: %v", p, err)
	}

	// Unknown / unsupported agent should be rejected
	pCustom := Provider{
		ID:      "custom",
		Name:    "Custom Provider",
		Account: &Account{Agent: "custom"},
		Chat:    "http://127.0.0.1:8080",
	}
	if err := Save(pCustom); err != nil {
		t.Fatalf("saving custom provider: %v", err)
	}
	if err := SetSwitchOnly("custom", true); err == nil {
		t.Fatal("expected error setting switch-only for non-whitelisted agent, got nil")
	}
}
