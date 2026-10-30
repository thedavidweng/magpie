package provider

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ============================================================================
// 1. ANTIGRAVITY KEYCHAIN & CORRUPTED DATA ADVERSARIAL TESTS
// ============================================================================

func TestAdversarial_AntigravityKeychainCorruptedData(t *testing.T) {
	fk, _ := isolateAntigravity(t)

	corruptCases := []struct {
		name    string
		payload []byte
	}{
		{"empty string", []byte("")},
		{"only whitespace", []byte("   \n\t  ")},
		{"prefix missing", []byte("eyJ0b2tlbiI6eyJtZXNzYWdlIjoiaGVsbG8ifX0=")},
		{"prefix with empty body", []byte(antigravityKeyringPrefix)},
		{"prefix with spaces body", []byte(antigravityKeyringPrefix + "    ")},
		{"prefix with invalid base64 (special chars)", []byte(antigravityKeyringPrefix + "!!!not-valid-b64???===")},
		{"prefix with truncated base64", []byte(antigravityKeyringPrefix + "YW55IGNhcm5hbCBwbGVhc3Vy")},
		{"valid base64 of empty string", []byte(antigravityKeyringPrefix + base64.StdEncoding.EncodeToString([]byte("")))},
		{"valid base64 of non-json plaintext", []byte(antigravityKeyringPrefix + base64.StdEncoding.EncodeToString([]byte("this is raw text, not json")))},
		{"valid base64 of JSON primitive string", []byte(antigravityKeyringPrefix + base64.StdEncoding.EncodeToString([]byte(`"just a string"`)))},
		{"valid base64 of JSON primitive number", []byte(antigravityKeyringPrefix + base64.StdEncoding.EncodeToString([]byte(`12345`)))},
		{"valid base64 of JSON array", []byte(antigravityKeyringPrefix + base64.StdEncoding.EncodeToString([]byte(`[1, 2, 3]`)))},
		{"valid base64 of JSON null", []byte(antigravityKeyringPrefix + base64.StdEncoding.EncodeToString([]byte(`null`)))},
		{"valid base64 of empty object {}", []byte(antigravityKeyringPrefix + base64.StdEncoding.EncodeToString([]byte(`{}`)))},
		{"valid base64 of token with empty strings", []byte(antigravityKeyringPrefix + base64.StdEncoding.EncodeToString([]byte(`{"token":{"access_token":"","refresh_token":""}}`)))},
		{"valid base64 of token object without tokens", []byte(antigravityKeyringPrefix + base64.StdEncoding.EncodeToString([]byte(`{"token":{"token_type":"Bearer"}}`)))},
		{"valid base64 of malformed truncated JSON", []byte(antigravityKeyringPrefix + base64.StdEncoding.EncodeToString([]byte(`{"token":{"access_token":"ya29.`)))},
	}

	for _, tc := range corruptCases {
		t.Run(tc.name, func(t *testing.T) {
			fk.items[antigravityKeychainAccount] = tc.payload
			got, ok, err := readAntigravityLogin()
			if err == nil {
				t.Errorf("[%s] Expected error on corrupted keychain payload, got nil (got: %+v, ok: %v)", tc.name, got, ok)
			}
			if ok {
				t.Errorf("[%s] Expected ok=false on corrupted keychain payload, got true", tc.name)
			}

			// liveLogin must also cleanly report false and not panic
			live, liveOk := antigravityLiveLogin()
			if liveOk {
				t.Errorf("[%s] Expected antigravityLiveLogin ok=false on corrupted keychain, got true (live: %+v)", tc.name, live)
			}
		})
	}
}

// Test what happens when Keychain returns a non-ErrNotExist error (e.g. refused or timeout)
type failingKeyring struct {
	*fakeKeychain
	findErr error
	putErr  error
}

func (f *failingKeyring) Find(service, account string) ([]byte, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	return f.fakeKeychain.Find(service, account)
}

func (f *failingKeyring) Put(service, account string, secret []byte) error {
	if f.putErr != nil {
		return f.putErr
	}
	return f.fakeKeychain.Put(service, account, secret)
}

func TestAdversarial_AntigravityKeychainErrorsNonFallback(t *testing.T) {
	fk, tmp := isolateAntigravity(t)

	// Put valid token files on disk
	cliToken := filepath.Join(tmp, ".gemini", "antigravity-cli", "antigravity-oauth-token")
	_ = os.MkdirAll(filepath.Dir(cliToken), 0700)
	_ = os.WriteFile(cliToken, sampleAntigravityAuth("disk-user@example.com"), 0600)

	// 1. If Keychain returns an authentic error like errKeychainRefused, it MUST NOT fall back to disk tokens
	// and MUST return the error (so user is aware keychain failed).
	antigravityKeychain = &failingKeyring{
		fakeKeychain: fk,
		findErr:      errors.New("access denied by user"),
	}

	_, ok, err := readAntigravityLogin()
	if err == nil {
		t.Fatalf("expected error when keychain returns unread error, got nil")
	}
	if ok {
		t.Fatalf("expected ok=false when keychain has access error, got true")
	}

	// 2. If Keychain returns fs.ErrNotExist, it SHOULD fall back to disk token file
	antigravityKeychain = &failingKeyring{
		fakeKeychain: fk,
		findErr:      fs.ErrNotExist,
	}
	got, ok, err := readAntigravityLogin()
	if err != nil {
		t.Fatalf("expected fallback to disk when keychain item not found, got err: %v", err)
	}
	if !ok || got.User != "disk-user@example.com" {
		t.Fatalf("expected user disk-user@example.com from disk fallback, got %+v, ok %v", got, ok)
	}
}

func TestAdversarial_AntigravityReadOnlyDir(t *testing.T) {
	_, tmp := isolateAntigravity(t)
	gemDir := filepath.Join(tmp, ".gemini")
	if err := os.MkdirAll(gemDir, 0500); err != nil { // read-only directory
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(gemDir, 0700)
	})

	want := savedLogin{
		Agent: "antigravity",
		User:  "test@example.com",
		Auth:  sampleAntigravityAuth("test@example.com"),
	}

	// Save should fail cleanly because it cannot create subdirectories or write files in .gemini
	err := saveAntigravityLogin(want)
	if err == nil {
		t.Fatal("expected saveAntigravityLogin to fail in read-only directory, got nil")
	}
}

// ============================================================================
// 2. FACTORY AES-256-GCM VAULT INTEGRITY & TAMPERING TESTS
// ============================================================================

func TestAdversarial_FactoryVaultTampering(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	origPayload := []byte(`{"access_token":"secret-token-xyz","email":"safe@factory.ai"}`)
	vault, err := encryptFactoryVault(key, origPayload)
	if err != nil {
		t.Fatalf("encryptFactoryVault failed: %v", err)
	}

	parts := strings.Split(vault, ":")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	ivBytes, _ := base64.StdEncoding.DecodeString(parts[0])
	tagBytes, _ := base64.StdEncoding.DecodeString(parts[1])
	ctBytes, _ := base64.StdEncoding.DecodeString(parts[2])

	// 1. Tamper with IV (flip 1 bit)
	tamperedIV := make([]byte, len(ivBytes))
	copy(tamperedIV, ivBytes)
	tamperedIV[0] ^= 0x01
	tamperedVaultIV := fmt.Sprintf("%s:%s:%s",
		base64.StdEncoding.EncodeToString(tamperedIV),
		parts[1],
		parts[2],
	)
	if _, err := decryptFactoryVault(key, tamperedVaultIV); err == nil {
		t.Fatal("expected decryption to FAIL when IV is tampered, but succeeded!")
	}

	// 2. Tamper with Auth Tag (flip 1 bit)
	tamperedTag := make([]byte, len(tagBytes))
	copy(tamperedTag, tagBytes)
	tamperedTag[0] ^= 0x01
	tamperedVaultTag := fmt.Sprintf("%s:%s:%s",
		parts[0],
		base64.StdEncoding.EncodeToString(tamperedTag),
		parts[2],
	)
	if _, err := decryptFactoryVault(key, tamperedVaultTag); err == nil {
		t.Fatal("expected decryption to FAIL when Auth Tag is tampered, but succeeded!")
	}

	// 3. Tamper with Ciphertext (flip 1 bit)
	tamperedCT := make([]byte, len(ctBytes))
	copy(tamperedCT, ctBytes)
	tamperedCT[0] ^= 0x01
	tamperedVaultCT := fmt.Sprintf("%s:%s:%s",
		parts[0],
		parts[1],
		base64.StdEncoding.EncodeToString(tamperedCT),
	)
	if _, err := decryptFactoryVault(key, tamperedVaultCT); err == nil {
		t.Fatal("expected decryption to FAIL when Ciphertext is tampered, but succeeded!")
	}

	// 4. Truncate Ciphertext
	truncatedCT := ctBytes[:len(ctBytes)/2]
	truncVault := fmt.Sprintf("%s:%s:%s",
		parts[0],
		parts[1],
		base64.StdEncoding.EncodeToString(truncatedCT),
	)
	if _, err := decryptFactoryVault(key, truncVault); err == nil {
		t.Fatal("expected decryption to FAIL on truncated ciphertext, but succeeded!")
	}

	// 5. Append byte to Ciphertext
	extendedCT := append(ctBytes, 0xFF)
	extVault := fmt.Sprintf("%s:%s:%s",
		parts[0],
		parts[1],
		base64.StdEncoding.EncodeToString(extendedCT),
	)
	if _, err := decryptFactoryVault(key, extVault); err == nil {
		t.Fatal("expected decryption to FAIL on extended ciphertext, but succeeded!")
	}
}

func TestAdversarial_FactoryWrongKeyLengths(t *testing.T) {
	payload := []byte(`{"access_token":"valid","email":"valid@factory.ai"}`)

	badKeyLengths := []int{0, 1, 8, 15, 16, 24, 31, 33, 48, 64, 128}

	for _, kl := range badKeyLengths {
		badKey := make([]byte, kl)
		rand.Read(badKey)

		// Encrypt must reject key length != 32
		if _, err := encryptFactoryVault(badKey, payload); err == nil {
			t.Errorf("[len %d] expected encryptFactoryVault to fail with key length %d, got nil", kl, kl)
		}

		// Decrypt must reject key length != 32
		if _, err := decryptFactoryVault(badKey, "aXY=:dGFn:Y3Q="); err == nil {
			t.Errorf("[len %d] expected decryptFactoryVault to fail with key length %d, got nil", kl, kl)
		}
	}
}

func TestAdversarial_FactoryVaultMalformedFormats(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	malformedVaults := []string{
		"",
		":",
		"::",
		":::",
		"singlepart",
		"two:parts",
		"four:parts:extra:colon",
		"   :   :   ",
		"invalid-b64-iv:validtag:validct",
		base64.StdEncoding.EncodeToString([]byte("1234567890123456")) + ":bad-b64:validct",
		base64.StdEncoding.EncodeToString([]byte("1234567890123456")) + ":" + base64.StdEncoding.EncodeToString([]byte("1234567890123456")) + ":not-b64-ct!!",
		// IV length wrong (12 bytes instead of 16)
		base64.StdEncoding.EncodeToString([]byte("123456789012")) + ":" + base64.StdEncoding.EncodeToString([]byte("1234567890123456")) + ":" + base64.StdEncoding.EncodeToString([]byte("ct")),
		// Tag length wrong (8 bytes instead of 16)
		base64.StdEncoding.EncodeToString([]byte("1234567890123456")) + ":" + base64.StdEncoding.EncodeToString([]byte("12345678")) + ":" + base64.StdEncoding.EncodeToString([]byte("ct")),
	}

	for _, mv := range malformedVaults {
		if _, err := decryptFactoryVault(key, mv); err == nil {
			t.Errorf("[%q] expected decryptFactoryVault to error on malformed vault format, got nil", mv)
		}
	}
}

// ============================================================================
// 3. EDGE CASES: UNICODE, EMPTY FIELDS, AND HUGE TOKENS
// ============================================================================

func TestAdversarial_AntigravityEdgeCases(t *testing.T) {
	fk, _ := isolateAntigravity(t)

	// A. Unicode Edge Cases (emojis, RTL Arabic, Chinese, Cyrillic, accented UTF-8)
	unicodeEmails := []string{
		"user+测试@example.com",
		"مستخدم@domain.com",
		"davy🚀developer@sub.domain.org",
		"иван.иванов@яндекс.рф",
		"üñîçødé@tëst.com",
		"zero\u200Bwidth\uFEFF@test.com",
	}

	for _, email := range unicodeEmails {
		t.Run("Unicode_"+email, func(t *testing.T) {
			want := savedLogin{
				Agent: "antigravity",
				User:  email,
				Auth:  sampleAntigravityAuth(email),
			}
			if err := saveAntigravityLogin(want); err != nil {
				t.Fatalf("saveAntigravityLogin failed with unicode email %q: %v", email, err)
			}
			got, ok, err := readAntigravityLogin()
			if err != nil || !ok {
				t.Fatalf("readAntigravityLogin failed: got ok=%v, err=%v", ok, err)
			}
			if got.User != email {
				t.Fatalf("user mismatch: got %q, want %q", got.User, email)
			}
		})
	}

	// B. Huge Token Payload (5 Megabytes)
	t.Run("HugePayload_5MB", func(t *testing.T) {
		hugeToken := strings.Repeat("A", 5*1024*1024)
		p := antigravityPayload{
			Token: antigravityToken{
				AccessToken:  hugeToken,
				RefreshToken: "refresh-" + strings.Repeat("B", 1024*1024),
			},
			IDTokenEmail: "huge@example.com",
		}
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		want := savedLogin{
			Agent: "antigravity",
			User:  "huge@example.com",
			Auth:  b,
		}
		if err := saveAntigravityLogin(want); err != nil {
			t.Fatalf("saveAntigravityLogin failed on huge payload: %v", err)
		}
		got, ok, err := readAntigravityLogin()
		if err != nil || !ok {
			t.Fatalf("readAntigravityLogin failed on huge payload: ok=%v, err=%v", ok, err)
		}
		if got.User != "huge@example.com" {
			t.Fatalf("huge payload user mismatch: %q", got.User)
		}
		var gotP antigravityPayload
		if err := json.Unmarshal(got.Auth, &gotP); err != nil {
			t.Fatalf("unmarshaling huge auth: %v", err)
		}
		if len(gotP.Token.AccessToken) != len(hugeToken) {
			t.Fatalf("huge access token length mismatch: got %d, want %d", len(gotP.Token.AccessToken), len(hugeToken))
		}
	})

	// C. Fallback User Resolution Hierarchy
	t.Run("FallbackDefaultUser", func(t *testing.T) {
		// Clean up google_accounts.json so activeGoogleAccount() doesn't pick up previous test's account
		_ = os.Remove(antigravityGoogleAccountsPath())

		// No email in token payload and User is empty
		p := antigravityPayload{
			Token: antigravityToken{
				AccessToken: "valid-token",
			},
		}
		b, _ := json.Marshal(p)
		// Put directly in keychain
		val := antigravityKeyringPrefix + base64.StdEncoding.EncodeToString(b)
		fk.items[antigravityKeychainAccount] = []byte(val)

		got, ok, err := readAntigravityLogin()
		if err != nil || !ok {
			t.Fatalf("expected read to succeed with default user: ok %v, err %v", ok, err)
		}
		if got.User != "Antigravity" {
			t.Fatalf("expected fallback user to be 'Antigravity', got %q", got.User)
		}

		// Now test when google_accounts.json has active account
		acctsJSON := []byte(`{"active":"google-acct@example.com","old":[]}`)
		_ = os.WriteFile(antigravityGoogleAccountsPath(), acctsJSON, 0600)
		gotAcct, okAcct, errAcct := readAntigravityLogin()
		if errAcct != nil || !okAcct {
			t.Fatalf("expected read to succeed with google_accounts.json: ok %v, err %v", okAcct, errAcct)
		}
		if gotAcct.User != "google-acct@example.com" {
			t.Fatalf("expected user from google_accounts.json, got %q", gotAcct.User)
		}
	})
}

func TestAdversarial_FactoryEdgeCases(t *testing.T) {
	isolateFactory(t)

	// A. Unicode Edge Cases (emojis, complex org names, unicode user IDs)
	unicodeCases := []struct {
		email string
		org   string
	}{
		{"developer@工廠.ai", "org_北京_01"},
		{"مطور@factory.ai", "org_العالمية"},
		{"🧑‍💻coder🚀@factory.ai", "org_🦄🌈_test"},
		{"test+unicode@domain.com", "org_\u200Bzero\u200Cwidth"},
	}

	for _, tc := range unicodeCases {
		t.Run("Unicode_"+tc.email, func(t *testing.T) {
			want := savedLogin{
				Agent: "factory",
				User:  tc.email,
				Auth:  sampleFactoryAuth(tc.email, tc.org),
			}
			if err := saveFactoryLogin(want); err != nil {
				t.Fatalf("saveFactoryLogin failed for unicode case %+v: %v", tc, err)
			}
			got, ok, err := readFactoryLogin()
			if err != nil || !ok {
				t.Fatalf("readFactoryLogin failed: ok %v, err %v", ok, err)
			}
			if got.User != tc.email {
				t.Fatalf("user mismatch: got %q, want %q", got.User, tc.email)
			}
		})
	}

	// B. Huge Payload (5 Megabytes)
	t.Run("HugePayload_5MB", func(t *testing.T) {
		hugeToken := strings.Repeat("F", 5*1024*1024)
		m := map[string]any{
			"access_token": hugeToken,
			"email":        "huge@factory.ai",
			"orgId":        "huge-org",
		}
		b, _ := json.Marshal(m)
		want := savedLogin{
			Agent: "factory",
			User:  "huge@factory.ai",
			Auth:  b,
		}
		if err := saveFactoryLogin(want); err != nil {
			t.Fatalf("saveFactoryLogin failed on huge payload: %v", err)
		}
		got, ok, err := readFactoryLogin()
		if err != nil || !ok {
			t.Fatalf("readFactoryLogin failed on huge payload: ok=%v, err=%v", ok, err)
		}
		if got.User != "huge@factory.ai" {
			t.Fatalf("user mismatch on huge payload: %q", got.User)
		}
		if !bytes.Equal(got.Auth, b) {
			t.Fatal("auth payload mismatch on huge payload roundtrip")
		}
	})

	// C. Fallback User Resolution Hierarchy
	t.Run("UserResolutionHierarchy", func(t *testing.T) {
		// 1. whoami.email when top-level email is missing
		m1 := map[string]any{"whoami": map[string]any{"email": "who@factory.ai"}}
		b1, _ := json.Marshal(m1)
		if u := factoryUserOf(b1); u != "who@factory.ai" {
			t.Fatalf("expected who@factory.ai, got %q", u)
		}

		// 2. whoami.userId when whoami.email is missing
		m2 := map[string]any{"whoami": map[string]any{"userId": "usr_999"}}
		b2, _ := json.Marshal(m2)
		if u := factoryUserOf(b2); u != "usr_999" {
			t.Fatalf("expected usr_999, got %q", u)
		}

		// 3. activeOrganizationId
		m3 := map[string]any{"activeOrganizationId": "org_active"}
		b3, _ := json.Marshal(m3)
		if u := factoryUserOf(b3); u != "org_active" {
			t.Fatalf("expected org_active, got %q", u)
		}

		// 4. orgId
		m4 := map[string]any{"orgId": "org_id_123"}
		b4, _ := json.Marshal(m4)
		if u := factoryUserOf(b4); u != "org_id_123" {
			t.Fatalf("expected org_id_123, got %q", u)
		}

		// 5. userId
		m5 := map[string]any{"userId": "user_id_456"}
		b5, _ := json.Marshal(m5)
		if u := factoryUserOf(b5); u != "user_id_456" {
			t.Fatalf("expected user_id_456, got %q", u)
		}

		// 6. Empty / unresolvable
		m6 := map[string]any{"random_field": "something"}
		b6, _ := json.Marshal(m6)
		if u := factoryUserOf(b6); u != "" {
			t.Fatalf("expected empty, got %q", u)
		}
	})
}

// ============================================================================
// 4. FALLBACK CHAIN AND KEYCHAIN RECOVERY
// ============================================================================

func TestAdversarial_AntigravityJetskiFallback(t *testing.T) {
	isolateAntigravity(t)
	antigravityKeychainHere = false // disable keychain

	// Ensure CLI token does NOT exist
	cliToken := antigravityCLIPath()
	_ = os.Remove(cliToken)

	// Create standalone Jetski token file
	jetskiToken := antigravityJetskiPath()
	_ = os.MkdirAll(filepath.Dir(jetskiToken), 0700)
	jetskiPayload := sampleAntigravityAuth("jetski-user@example.com")
	if err := os.WriteFile(jetskiToken, jetskiPayload, 0600); err != nil {
		t.Fatal(err)
	}

	got, ok, err := readAntigravityLogin()
	if err != nil || !ok {
		t.Fatalf("readAntigravityLogin failed: got ok=%v, err=%v", ok, err)
	}
	if got.User != "jetski-user@example.com" {
		t.Fatalf("expected user from jetski standalone token, got %q", got.User)
	}
}

func TestAdversarial_FactoryKeychainFallbackToFile(t *testing.T) {
	fk, tmp := isolateFactory(t)
	// Keychain is enabled on darwin, but keychain has NO entry
	// Only auth.v2.file and auth.v2.key exist on disk
	delete(fk.items, factoryKeychainAccount)

	dir := filepath.Join(tmp, ".factory")
	_ = os.MkdirAll(dir, 0700)
	key := make([]byte, 32)
	rand.Read(key)
	authJSON := sampleFactoryAuth("file-user@factory.ai", "org_file")
	vault, err := encryptFactoryVault(key, authJSON)
	if err != nil {
		t.Fatal(err)
	}

	_ = os.WriteFile(filepath.Join(dir, "auth.v2.key"), []byte(base64.StdEncoding.EncodeToString(key)), 0600)
	_ = os.WriteFile(filepath.Join(dir, "auth.v2.file"), []byte(vault), 0600)

	got, ok, err := readFactoryLogin()
	if err != nil || !ok {
		t.Fatalf("readFactoryLogin failed to fallback to file: ok=%v, err=%v", ok, err)
	}
	if got.User != "file-user@factory.ai" {
		t.Fatalf("expected file-user@factory.ai, got %q", got.User)
	}
}
