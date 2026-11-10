package provider

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

const (
	antigravityKeychainService = "gemini"
	antigravityKeychainAccount = "antigravity"
	antigravityKeyringPrefix   = "go-keyring-base64:"
)

var (
	antigravityKeychain     keychain = securityKeychain{}
	antigravityKeychainHere          = runtime.GOOS == "darwin"
)

type antigravityToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Expiry       string `json:"expiry,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

type antigravityPayload struct {
	Token        antigravityToken `json:"token"`
	AuthMethod   string           `json:"auth_method,omitempty"`
	IDTokenEmail string           `json:"id_token_email,omitempty"`
	Email        string           `json:"email,omitempty"`
}

func antigravityCLIPath() string {
	return filepath.Join(geminiDir(), "antigravity-cli", "antigravity-oauth-token")
}

func antigravityJetskiPath() string {
	return filepath.Join(geminiDir(), "jetski-standalone-oauth-token")
}

func antigravityGoogleAccountsPath() string {
	return filepath.Join(geminiDir(), "google_accounts.json")
}

// parseAntigravityPayload decodes and validates a raw JSON byte slice into antigravityPayload.
func parseAntigravityPayload(b []byte) (antigravityPayload, error) {
	var p antigravityPayload
	if err := json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	if p.Token.AccessToken == "" && p.Token.RefreshToken == "" {
		return p, errors.New("antigravity token payload missing tokens")
	}
	return p, nil
}

// activeGoogleAccount reads the "active" email from ~/.gemini/google_accounts.json if present.
func activeGoogleAccount() string {
	b, err := os.ReadFile(antigravityGoogleAccountsPath())
	if err != nil {
		return ""
	}
	var accts struct {
		Active string `json:"active"`
	}
	if json.Unmarshal(b, &accts) == nil {
		return accts.Active
	}
	return ""
}

// readAntigravityLogin reads the active Antigravity sign-in from the macOS Keychain
// (when available) or fallback token files on disk.
func readAntigravityLogin() (savedLogin, bool, error) {
	if antigravityKeychainHere {
		secret, err := antigravityKeychain.Find(antigravityKeychainService, antigravityKeychainAccount)
		if err == nil {
			trimmed := strings.TrimSpace(string(secret))
			if !strings.HasPrefix(trimmed, antigravityKeyringPrefix) {
				return savedLogin{}, false, fmt.Errorf("antigravity keychain item missing %s prefix", antigravityKeyringPrefix)
			}
			rawB64 := strings.TrimPrefix(trimmed, antigravityKeyringPrefix)
			payloadBytes, decErr := base64.StdEncoding.DecodeString(rawB64)
			if decErr != nil {
				return savedLogin{}, false, fmt.Errorf("corrupt antigravity keychain base64: %w", decErr)
			}
			p, parseErr := parseAntigravityPayload(payloadBytes)
			if parseErr != nil {
				return savedLogin{}, false, fmt.Errorf("corrupt antigravity keychain payload: %w", parseErr)
			}
			user := p.IDTokenEmail
			if user == "" {
				user = p.Email
			}
			if user == "" {
				user = activeGoogleAccount()
			}
			if user == "" {
				user = "Antigravity"
			}
			return savedLogin{
				Agent: "antigravity",
				User:  user,
				Auth:  json.RawMessage(payloadBytes),
			}, true, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return savedLogin{}, false, fmt.Errorf("reading antigravity keychain: %w", err)
		}
	}

	// Fallback to disk token files: first CLI token, then standalone fallback
	paths := []string{antigravityCLIPath(), antigravityJetskiPath()}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err == nil {
			p, parseErr := parseAntigravityPayload(b)
			if parseErr != nil {
				return savedLogin{}, false, fmt.Errorf("corrupt antigravity token file %s: %w", path, parseErr)
			}
			user := p.IDTokenEmail
			if user == "" {
				user = p.Email
			}
			if user == "" {
				user = activeGoogleAccount()
			}
			if user == "" {
				user = "Antigravity"
			}
			return savedLogin{
				Agent: "antigravity",
				User:  user,
				Auth:  json.RawMessage(b),
			}, true, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return savedLogin{}, false, fmt.Errorf("reading antigravity file %s: %w", path, err)
		}
	}

	return savedLogin{}, false, nil
}

// saveAntigravityLogin dual-writes active Antigravity credentials:
// 1. macOS Keychain (when on Darwin) using `security add-generic-password -U`
// 2. ~/.gemini/antigravity-cli/antigravity-oauth-token (0600)
// 3. ~/.gemini/jetski-standalone-oauth-token (0600)
// 4. ~/.gemini/google_accounts.json (updating active account)
func saveAntigravityLogin(want savedLogin) error {
	if len(want.Auth) == 0 {
		return errors.New("cannot save empty antigravity login")
	}

	var p antigravityPayload
	if err := json.Unmarshal(want.Auth, &p); err != nil {
		return fmt.Errorf("invalid antigravity auth json: %w", err)
	}

	if p.Token.AccessToken == "" && p.Token.RefreshToken == "" {
		var ga googleAuth
		if json.Unmarshal(want.Auth, &ga) == nil && (ga.AccessToken != "" || ga.RefreshToken != "") {
			p.Token.AccessToken = ga.AccessToken
			p.Token.RefreshToken = ga.RefreshToken
			p.Token.TokenType = "Bearer"
		}
	}

	if p.IDTokenEmail == "" && want.User != "" && want.User != "Antigravity" {
		p.IDTokenEmail = want.User
	}
	if p.AuthMethod == "" {
		p.AuthMethod = "consumer"
	}

	payloadBytes, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshaling antigravity payload: %w", err)
	}

	// 1. Write to Keychain on Darwin
	if antigravityKeychainHere {
		val := antigravityKeyringPrefix + base64.StdEncoding.EncodeToString(payloadBytes)
		if putErr := antigravityKeychain.Put(antigravityKeychainService, antigravityKeychainAccount, []byte(val)); putErr != nil {
			return fmt.Errorf("saving antigravity to keychain: %w", putErr)
		}
	}

	// 2. Dual-write token files
	if err := writePrivate(antigravityCLIPath(), payloadBytes); err != nil {
		return fmt.Errorf("writing %s: %w", antigravityCLIPath(), err)
	}
	if err := writePrivate(antigravityJetskiPath(), payloadBytes); err != nil {
		return fmt.Errorf("writing %s: %w", antigravityJetskiPath(), err)
	}

	// 3. Update google_accounts.json
	acctsPath := antigravityGoogleAccountsPath()
	var accts struct {
		Active string   `json:"active"`
		Old    []string `json:"old"`
	}
	if b, err := os.ReadFile(acctsPath); err == nil {
		_ = json.Unmarshal(b, &accts)
	}
	if accts.Active != "" && accts.Active != want.User {
		if !slices.Contains(accts.Old, accts.Active) {
			accts.Old = append(accts.Old, accts.Active)
		}
	}
	accts.Active = want.User
	if accts.Old == nil {
		accts.Old = []string{}
	}
	out, err := json.MarshalIndent(accts, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling google_accounts: %w", err)
	}
	if err := writePrivate(acctsPath, out); err != nil {
		return fmt.Errorf("writing %s: %w", acctsPath, err)
	}

	return nil
}

// antigravityLiveLogin reads the account Antigravity is signed in to now.
func antigravityLiveLogin() (savedLogin, bool) {
	l, ok, err := readAntigravityLogin()
	if err != nil || !ok {
		return savedLogin{}, false
	}
	return l, true
}
