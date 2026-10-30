package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/plugin"
	"github.com/yetone/magpie/internal/provider"
)

func runCaptureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fnErr := fn()
	w.Close()
	os.Stdout = old
	out := <-done
	r.Close()
	return out, fnErr
}

func TestSwitchOnlyCmdValidation(t *testing.T) {
	const usage = "usage: magpie accounts switch-only <codex|claude|antigravity|factory> [on|off]"

	// Empty args
	if err := switchOnlyCmd([]string{}); err == nil || !strings.Contains(err.Error(), usage) {
		t.Fatalf("expected usage error for empty args, got: %v", err)
	}

	// Too many args
	if err := switchOnlyCmd([]string{"antigravity", "on", "extra"}); err == nil || !strings.Contains(err.Error(), usage) {
		t.Fatalf("expected usage error for 3 args, got: %v", err)
	}

	// Unsupported agent
	if err := switchOnlyCmd([]string{"unsupported"}); err == nil || !strings.Contains(err.Error(), usage) {
		t.Fatalf("expected usage error for unsupported agent, got: %v", err)
	}

	// Invalid state option
	if err := switchOnlyCmd([]string{"antigravity", "invalid"}); err == nil || !strings.Contains(err.Error(), usage) {
		t.Fatalf("expected usage error for invalid on/off option, got: %v", err)
	}
}

func TestSwitchOnlyCmdExecution(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configDir := filepath.Join(home, ".config", "magpie")
	t.Setenv("XDG_CONFIG_HOME", filepath.Dir(configDir))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))

	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Write logins so Accounts() discovers antigravity
	futureExpiry := time.Now().Add(24 * time.Hour).UnixMilli()
	logins := []map[string]any{
		{
			"agent": "antigravity",
			"user":  "developer@example.com",
			"auth": map[string]any{
				"access_token":  "mock-access-token",
				"refresh_token": "sample-refresh-token",
				"expiry":        futureExpiry,
			},
		},
		{
			"agent": "antigravity",
			"user":  "developer2@example.com",
			"auth": map[string]any{
				"access_token":  "mock-access-token-2",
				"refresh_token": "sample-refresh-token-2",
				"expiry":        futureExpiry,
			},
		},
	}
	lb, err := json.Marshal(logins)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "logins.json"), lb, 0o600); err != nil {
		t.Fatal(err)
	}

	// Set up Factory plugin cache
	pluginAuth := map[string]any{
		"factory": map[string]any{
			"type":      "oauth",
			"access":    "sample-access-token",
			"refresh":   "sample-refresh-token",
			"expires":   futureExpiry,
			"accountId": "user@factory.ai",
		},
		"factory#2": map[string]any{
			"type":      "oauth",
			"access":    "sample-access-token-2",
			"refresh":   "sample-refresh-token-2",
			"expires":   futureExpiry,
			"accountId": "user2@factory.ai",
		},
	}
	pab, err := json.Marshal(pluginAuth)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "plugin-auth.json"), pab, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "plugins.json"), []byte(`{"plugins":[{"spec":"@magpie-community/opencode-factory-auth"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	plugin.UseCached([]plugin.Provider{{
		ID:   "factory",
		Spec: "@magpie-community/opencode-factory-auth",
		Name: "Factory",
		Accounts: []plugin.Account{
			{
				Key:       "factory",
				AccountID: "user@factory.ai",
			},
			{
				Key:       "factory#2",
				AccountID: "user2@factory.ai",
			},
		},
		Models: []plugin.Model{
			{ID: "factory-model", NPM: "@ai-sdk/openai"},
		},
	}})
	t.Cleanup(func() { plugin.UseCached(nil) })

	provider.ForgetAccounts()
	t.Cleanup(provider.ForgetAccounts)

	// 1. Antigravity query initial state (off by default)
	out, err := runCaptureStdout(t, func() error {
		return switchOnlyCmd([]string{"antigravity"})
	})
	if err != nil {
		t.Fatalf("query antigravity switch-only: %v", err)
	}
	if !strings.Contains(out, "off · magpie serves requests on the Antigravity accounts that are on") {
		t.Fatalf("unexpected query off output: %q", out)
	}

	// 2. Set Antigravity switch-only on
	out, err = runCaptureStdout(t, func() error {
		return switchOnlyCmd([]string{"antigravity", "on"})
	})
	if err != nil {
		t.Fatalf("set antigravity on: %v", err)
	}
	if !strings.Contains(out, "magpie only switches Antigravity's sign-in to an account with room; its requests go straight to Google") {
		t.Fatalf("unexpected set on output: %q", out)
	}

	// Query again (should be on)
	out, err = runCaptureStdout(t, func() error {
		return switchOnlyCmd([]string{"antigravity"})
	})
	if err != nil {
		t.Fatalf("query antigravity switch-only: %v", err)
	}
	if !strings.Contains(out, "on · magpie only switches Antigravity's sign-in; its requests go straight to Google") {
		t.Fatalf("unexpected query on output: %q", out)
	}

	// 3. Set Antigravity switch-only off using alias "agy"
	out, err = runCaptureStdout(t, func() error {
		return switchOnlyCmd([]string{"agy", "off"})
	})
	if err != nil {
		t.Fatalf("set agy off: %v", err)
	}
	if !strings.Contains(out, "magpie serves requests on the Antigravity accounts that are on again") {
		t.Fatalf("unexpected set off output: %q", out)
	}

	// 4. Factory switch-only on using alias "droid"
	out, err = runCaptureStdout(t, func() error {
		return switchOnlyCmd([]string{"droid", "on"})
	})
	if err != nil {
		t.Fatalf("set droid on: %v", err)
	}
	if !strings.Contains(out, "magpie only switches Factory's sign-in to an account with room; its requests go straight to Factory") {
		t.Fatalf("unexpected set factory on output: %q", out)
	}

	// Query Factory switch-only status
	out, err = runCaptureStdout(t, func() error {
		return switchOnlyCmd([]string{"factory"})
	})
	if err != nil {
		t.Fatalf("query factory switch-only: %v", err)
	}
	if !strings.Contains(out, "on · magpie only switches Factory's sign-in; its requests go straight to Factory") {
		t.Fatalf("unexpected query factory on output: %q", out)
	}

	// 5. Turn Factory switch-only off
	out, err = runCaptureStdout(t, func() error {
		return switchOnlyCmd([]string{"factory", "off"})
	})
	if err != nil {
		t.Fatalf("set factory off: %v", err)
	}
	if !strings.Contains(out, "magpie serves requests on the Factory accounts that are on again") {
		t.Fatalf("unexpected set factory off output: %q", out)
	}

	// Verify query Factory off
	out, err = runCaptureStdout(t, func() error {
		return switchOnlyCmd([]string{"factory"})
	})
	if err != nil {
		t.Fatalf("query factory switch-only: %v", err)
	}
	if !strings.Contains(out, "off · magpie serves requests on the Factory accounts that are on") {
		t.Fatalf("unexpected query factory off output: %q", out)
	}

	// 6. Test accounts switch authentic feedback messages for antigravity and factory
	out, err = runCaptureStdout(t, func() error {
		return accountsCmd([]string{"accounts", "switch", "antigravity", "developer2@example.com"})
	})
	if err != nil {
		t.Fatalf("accounts switch antigravity: %v", err)
	}
	if !strings.Contains(out, "antigravity is now signed in as developer2@example.com") ||
		!strings.Contains(out, "sessions already running keep their account until restarted") {
		t.Fatalf("unexpected accounts switch antigravity output: %q", out)
	}

	out, err = runCaptureStdout(t, func() error {
		return accountsCmd([]string{"accounts", "switch", "factory", "user2@factory.ai"})
	})
	if err != nil {
		t.Fatalf("accounts switch factory: %v", err)
	}
	if !strings.Contains(out, "factory is now signed in as user2@factory.ai") ||
		!strings.Contains(out, "sessions already running keep their account until restarted") {
		t.Fatalf("unexpected accounts switch factory output: %q", out)
	}
}
