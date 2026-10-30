package provider

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	factoryKeychainService = "Factory CLI"
	factoryKeychainAccount = "auth-encryption-key-security-cli"
)

var (
	factoryKeychain     keychain = securityKeychain{}
	factoryKeychainHere          = runtime.GOOS == "darwin"
)

func factoryDir() string {
	if dir := os.Getenv("FACTORY_HOME_OVERRIDE"); dir != "" {
		if filepath.Base(dir) == ".factory" {
			return dir
		}
		return filepath.Join(dir, ".factory")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".factory")
}

func factoryKeyPath() string {
	return filepath.Join(factoryDir(), "auth.v2.key")
}

func factoryFilePath() string {
	return filepath.Join(factoryDir(), "auth.v2.file")
}

func factoryLoginKeychainPath() string {
	return filepath.Join(factoryDir(), "auth.v2.loginkeychain")
}

// encryptFactoryVault encrypts plaintext using AES-256-GCM with a 16-byte nonce,
// matching Droid CLI's wire format: ${base64(IV)}:${base64(AuthTag)}:${base64(Ciphertext)}.
func encryptFactoryVault(key []byte, plaintext []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("factory key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return "", err
	}
	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, plaintext, nil)
	if len(sealed) < 16 {
		return "", errors.New("factory seal produced invalid output")
	}
	tag := sealed[len(sealed)-16:]
	ciphertext := sealed[:len(sealed)-16]

	return fmt.Sprintf("%s:%s:%s",
		base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(tag),
		base64.StdEncoding.EncodeToString(ciphertext),
	), nil
}

// decryptFactoryVault decrypts Droid CLI's wire format: ${base64(IV)}:${base64(AuthTag)}:${base64(Ciphertext)}.
func decryptFactoryVault(key []byte, vault string) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("factory key must be 32 bytes")
	}
	parts := strings.Split(strings.TrimSpace(vault), ":")
	if len(parts) != 3 {
		return nil, errors.New("invalid factory vault format: expected 3 colon-separated parts")
	}
	iv, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil || len(iv) != 16 {
		return nil, errors.New("invalid factory vault IV")
	}
	tag, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(tag) != 16 {
		return nil, errors.New("invalid factory vault auth tag")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid factory vault ciphertext")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}
	sealed := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("factory vault decryption failed: %w", err)
	}
	return plaintext, nil
}

func factoryUserOf(b []byte) string {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	if email, ok := m["email"].(string); ok && email != "" {
		return email
	}
	if whoami, ok := m["whoami"].(map[string]any); ok {
		if email, ok := whoami["email"].(string); ok && email != "" {
			return email
		}
		if userID, ok := whoami["userId"].(string); ok && userID != "" {
			return userID
		}
	}
	if org, ok := m["active_organization_id"].(string); ok && org != "" {
		return org
	}
	if org, ok := m["activeOrganizationId"].(string); ok && org != "" {
		return org
	}
	if org, ok := m["orgId"].(string); ok && org != "" {
		return org
	}
	if user, ok := m["userId"].(string); ok && user != "" {
		return user
	}
	return ""
}

// readFactoryLogin reads active Factory (Droid CLI) credentials from
// ~/.factory/auth.v2.loginkeychain + Keychain on macOS Darwin, or
// ~/.factory/auth.v2.file + auth.v2.key.
func readFactoryLogin() (savedLogin, bool, error) {
	if factoryKeychainHere {
		loginkeychainFile := factoryLoginKeychainPath()
		if _, err := os.Stat(loginkeychainFile); err == nil {
			secret, kErr := factoryKeychain.Find(factoryKeychainService, factoryKeychainAccount)
			if kErr == nil {
				key, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(secret)))
				if decErr != nil || len(key) != 32 {
					return savedLogin{}, false, fmt.Errorf("invalid factory key in keychain: %w", decErr)
				}
				vaultBytes, rErr := os.ReadFile(loginkeychainFile)
				if rErr != nil {
					return savedLogin{}, false, fmt.Errorf("reading %s: %w", loginkeychainFile, rErr)
				}
				plaintext, decrErr := decryptFactoryVault(key, string(vaultBytes))
				if decrErr != nil {
					return savedLogin{}, false, fmt.Errorf("decrypting factory loginkeychain: %w", decrErr)
				}
				user := factoryUserOf(plaintext)
				if user == "" {
					user = "Factory"
				}
				return savedLogin{
					Agent: "factory",
					User:  user,
					Auth:  json.RawMessage(plaintext),
				}, true, nil
			}
			if !errors.Is(kErr, fs.ErrNotExist) {
				return savedLogin{}, false, fmt.Errorf("reading factory keychain: %w", kErr)
			}
		}
	}

	keyFile := factoryKeyPath()
	authFile := factoryFilePath()

	keyBytes, keyErr := os.ReadFile(keyFile)
	authBytes, authErr := os.ReadFile(authFile)

	if errors.Is(keyErr, fs.ErrNotExist) && errors.Is(authErr, fs.ErrNotExist) {
		return savedLogin{}, false, nil
	}
	if keyErr != nil {
		return savedLogin{}, false, fmt.Errorf("reading %s: %w", keyFile, keyErr)
	}
	if authErr != nil {
		return savedLogin{}, false, fmt.Errorf("reading %s: %w", authFile, authErr)
	}

	key, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyBytes)))
	if decErr != nil || len(key) != 32 {
		return savedLogin{}, false, errors.New("corrupt factory key in auth.v2.key")
	}

	plaintext, decrErr := decryptFactoryVault(key, string(authBytes))
	if decrErr != nil {
		return savedLogin{}, false, fmt.Errorf("decrypting factory auth file: %w", decrErr)
	}

	user := factoryUserOf(plaintext)
	if user == "" {
		user = "Factory"
	}

	return savedLogin{
		Agent: "factory",
		User:  user,
		Auth:  json.RawMessage(plaintext),
	}, true, nil
}

// saveFactoryLogin saves Factory (Droid CLI) credentials:
// 1. Generates 32-byte key
// 2. Encrypts payload with AES-256-GCM
// 3. Writes auth.v2.key and auth.v2.file (0600)
// 4. On macOS Darwin, updates Keychain and writes auth.v2.loginkeychain (0600)
func saveFactoryLogin(want savedLogin) error {
	if len(want.Auth) == 0 {
		return errors.New("cannot save empty factory login")
	}

	var raw map[string]any
	if err := json.Unmarshal(want.Auth, &raw); err != nil {
		return fmt.Errorf("invalid factory auth json: %w", err)
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("generating factory key: %w", err)
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)

	vault, err := encryptFactoryVault(key, want.Auth)
	if err != nil {
		return fmt.Errorf("encrypting factory vault: %w", err)
	}

	if err := writePrivate(factoryKeyPath(), []byte(keyB64)); err != nil {
		return fmt.Errorf("writing %s: %w", factoryKeyPath(), err)
	}
	if err := writePrivate(factoryFilePath(), []byte(vault)); err != nil {
		return fmt.Errorf("writing %s: %w", factoryFilePath(), err)
	}

	if factoryKeychainHere {
		if putErr := factoryKeychain.Put(factoryKeychainService, factoryKeychainAccount, []byte(keyB64)); putErr != nil {
			return fmt.Errorf("saving factory key to keychain: %w", putErr)
		}
		if err := writePrivate(factoryLoginKeychainPath(), []byte(vault)); err != nil {
			return fmt.Errorf("writing %s: %w", factoryLoginKeychainPath(), err)
		}
	}

	return nil
}

// factoryLiveLogin reads the account Factory is signed in to now.
func factoryLiveLogin() (savedLogin, bool) {
	l, ok, err := readFactoryLogin()
	if err != nil || !ok {
		return savedLogin{}, false
	}
	return l, true
}
