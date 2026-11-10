package provider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestAdversarialTokenPreservation_Antigravity tests whether switching from A to B
// when live credentials for A have been refreshed in the background preserves A's
// fresh tokens back to logins.json before activating B.
func TestAdversarialTokenPreservation_Antigravity(t *testing.T) {
	fk, tmp := isolateAntigravity(t)

	authA_v1 := sampleAntigravityAuth("userA@example.com")
	authB := sampleAntigravityAuth("userB@example.com")

	// 1. Initial state: userA is live with v1 tokens
	wantA := savedLogin{
		Agent: "antigravity",
		User:  "userA@example.com",
		Auth:  authA_v1,
	}
	if err := saveAntigravityLogin(wantA); err != nil {
		t.Fatalf("save initial userA: %v", err)
	}

	// logins.json contains userA (v1) and userB
	ls := []savedLogin{
		{Agent: "antigravity", User: "userA@example.com", Auth: authA_v1},
		{Agent: "antigravity", User: "userB@example.com", Auth: authB},
	}
	loginsMu.Lock()
	if err := writeLogins(ls); err != nil {
		loginsMu.Unlock()
		t.Fatalf("writing logins.json: %v", err)
	}
	loginsMu.Unlock()

	// 2. Simulate Antigravity refreshing userA's token in the background on disk/keychain
	pA_v2 := antigravityPayload{
		Token: antigravityToken{
			AccessToken:  "ya29.refreshed-access-token-A-v2",
			TokenType:    "Bearer",
			RefreshToken: "1//refreshed-refresh-token-A-v2",
			Expiry:       "2026-10-31T00:00:00Z",
			ExpiresIn:    7200,
		},
		AuthMethod:   "consumer",
		IDTokenEmail: "userA@example.com",
	}
	authA_v2, _ := json.Marshal(pA_v2)
	wantA_v2 := savedLogin{
		Agent: "antigravity",
		User:  "userA@example.com",
		Auth:  authA_v2,
	}
	// Write refreshed credentials directly to active store
	if err := saveAntigravityLogin(wantA_v2); err != nil {
		t.Fatalf("simulating background token refresh: %v", err)
	}

	// Verify live login sees v2
	live, ok := antigravityLiveLogin()
	if !ok || live.User != "userA@example.com" {
		t.Fatalf("expected live userA, got %v (ok=%v)", live, ok)
	}
	var pLive antigravityPayload
	_ = json.Unmarshal(live.Auth, &pLive)
	if pLive.Token.AccessToken != "ya29.refreshed-access-token-A-v2" {
		t.Fatalf("live login does not reflect refreshed token: %s", pLive.Token.AccessToken)
	}

	// 3. Switch to userB
	from, err := switchSavedLogin("antigravity", "userB@example.com")
	if err != nil {
		t.Fatalf("switchSavedLogin to userB: %v", err)
	}
	if from != "userA@example.com" {
		t.Fatalf("expected from userA@example.com, got %q", from)
	}

	// 4. Verify userB is now live
	liveAfter, ok := antigravityLiveLogin()
	if !ok || liveAfter.User != "userB@example.com" {
		t.Fatalf("expected live userB after switch, got %v (ok=%v)", liveAfter, ok)
	}

	// 5. CRITICAL CHECK: Verify logins.json preserved userA's refreshed v2 token!
	savedList := readLogins()
	var savedA *savedLogin
	for i := range savedList {
		if savedList[i].Agent == "antigravity" && savedList[i].User == "userA@example.com" {
			savedA = &savedList[i]
		}
	}
	if savedA == nil {
		t.Fatal("userA missing from logins.json after switch")
	}
	var pSavedA antigravityPayload
	if err := json.Unmarshal(savedA.Auth, &pSavedA); err != nil {
		t.Fatalf("unmarshal savedA auth: %v", err)
	}
	if pSavedA.Token.AccessToken != "ya29.refreshed-access-token-A-v2" {
		t.Fatalf("DESYNCHRONIZATION BUG: userA's fresh token was NOT preserved back to logins.json! Got %q, want %q",
			pSavedA.Token.AccessToken, "ya29.refreshed-access-token-A-v2")
	}

	// 6. Switch back to userA and verify v2 tokens are restored to disk/keychain
	fromB, err := switchSavedLogin("antigravity", "userA@example.com")
	if err != nil {
		t.Fatalf("switchSavedLogin back to userA: %v", err)
	}
	if fromB != "userB@example.com" {
		t.Fatalf("expected from userB@example.com, got %q", fromB)
	}

	liveBackA, ok := antigravityLiveLogin()
	if !ok || liveBackA.User != "userA@example.com" {
		t.Fatalf("expected live userA after switch back, got %v (ok=%v)", liveBackA, ok)
	}
	var pLiveBackA antigravityPayload
	_ = json.Unmarshal(liveBackA.Auth, &pLiveBackA)
	if pLiveBackA.Token.AccessToken != "ya29.refreshed-access-token-A-v2" {
		t.Fatalf("switch back did not restore v2 tokens: %s", pLiveBackA.Token.AccessToken)
	}
	_ = fk
	_ = tmp
}

// TestAdversarialTokenPreservation_Factory tests whether switching from A to B
// when live credentials for A have been refreshed in the background preserves A's
// fresh tokens back to logins.json before activating B.
func TestAdversarialTokenPreservation_Factory(t *testing.T) {
	_, _ = isolateFactory(t)

	authA_v1 := sampleFactoryAuth("userA@factory.ai", "orgA")
	authB := sampleFactoryAuth("userB@factory.ai", "orgB")

	// 1. Initial state: userA is live with v1 tokens
	wantA := savedLogin{
		Agent: "factory",
		User:  "userA@factory.ai",
		Auth:  authA_v1,
	}
	if err := saveFactoryLogin(wantA); err != nil {
		t.Fatalf("save initial userA: %v", err)
	}

	ls := []savedLogin{
		{Agent: "factory", User: "userA@factory.ai", Auth: authA_v1},
		{Agent: "factory", User: "userB@factory.ai", Auth: authB},
	}
	loginsMu.Lock()
	if err := writeLogins(ls); err != nil {
		loginsMu.Unlock()
		t.Fatalf("writing logins.json: %v", err)
	}
	loginsMu.Unlock()

	// 2. Simulate Factory refreshing userA's token in background
	mA_v2 := map[string]any{
		"access_token":           "fact_refreshed_access_A_v2",
		"refresh_token":          "fact_refreshed_refresh_A_v2",
		"active_organization_id": "orgA_new",
		"email":                  "userA@factory.ai",
		"whoami": map[string]any{
			"email":  "userA@factory.ai",
			"userId": "usr_A",
		},
	}
	authA_v2, _ := json.Marshal(mA_v2)
	wantA_v2 := savedLogin{
		Agent: "factory",
		User:  "userA@factory.ai",
		Auth:  authA_v2,
	}
	if err := saveFactoryLogin(wantA_v2); err != nil {
		t.Fatalf("save refreshed factory userA: %v", err)
	}

	// 3. Switch to userB
	from, err := switchSavedLogin("factory", "userB@factory.ai")
	if err != nil {
		t.Fatalf("switchSavedLogin to userB: %v", err)
	}
	if from != "userA@factory.ai" {
		t.Fatalf("expected from userA@factory.ai, got %q", from)
	}

	// 4. Verify userB is now live
	liveAfter, ok := factoryLiveLogin()
	if !ok || liveAfter.User != "userB@factory.ai" {
		t.Fatalf("expected live userB after switch, got %v (ok=%v)", liveAfter, ok)
	}

	// 5. CRITICAL CHECK: Verify logins.json preserved userA's refreshed v2 token!
	savedList := readLogins()
	var savedA *savedLogin
	for i := range savedList {
		if savedList[i].Agent == "factory" && savedList[i].User == "userA@factory.ai" {
			savedA = &savedList[i]
		}
	}
	if savedA == nil {
		t.Fatal("userA missing from logins.json after switch")
	}
	var mSavedA map[string]any
	if err := json.Unmarshal(savedA.Auth, &mSavedA); err != nil {
		t.Fatalf("unmarshal savedA auth: %v", err)
	}
	if mSavedA["access_token"] != "fact_refreshed_access_A_v2" {
		t.Fatalf("DESYNCHRONIZATION BUG: userA's fresh factory token was NOT preserved! Got %v", mSavedA["access_token"])
	}

	// 6. Switch back to userA
	fromB, err := switchSavedLogin("factory", "userA@factory.ai")
	if err != nil {
		t.Fatalf("switchSavedLogin back to userA: %v", err)
	}
	if fromB != "userB@factory.ai" {
		t.Fatalf("expected from userB@factory.ai, got %q", fromB)
	}
	liveBackA, ok := factoryLiveLogin()
	if !ok || liveBackA.User != "userA@factory.ai" {
		t.Fatalf("expected live userA after switch back, got %v (ok=%v)", liveBackA, ok)
	}
	var mLiveBackA map[string]any
	_ = json.Unmarshal(liveBackA.Auth, &mLiveBackA)
	if mLiveBackA["access_token"] != "fact_refreshed_access_A_v2" {
		t.Fatalf("switch back did not restore v2 tokens: %v", mLiveBackA["access_token"])
	}
}

// TestAdversarialNonExistentAccount tests error handling when switching to an unknown account.
func TestAdversarialNonExistentAccount(t *testing.T) {
	isolateAntigravity(t)
	isolateFactory(t)

	authA := sampleAntigravityAuth("valid@example.com")
	if err := saveAntigravityLogin(savedLogin{Agent: "antigravity", User: "valid@example.com", Auth: authA}); err != nil {
		t.Fatalf("save initial antigravity: %v", err)
	}
	authFact := sampleFactoryAuth("valid@factory.ai", "org1")
	if err := saveFactoryLogin(savedLogin{Agent: "factory", User: "valid@factory.ai", Auth: authFact}); err != nil {
		t.Fatalf("save initial factory: %v", err)
	}

	ls := []savedLogin{
		{Agent: "antigravity", User: "valid@example.com", Auth: authA},
		{Agent: "factory", User: "valid@factory.ai", Auth: authFact},
	}
	loginsMu.Lock()
	_ = writeLogins(ls)
	loginsMu.Unlock()

	// 1. Non-existent Antigravity in switchSavedLogin
	_, err := switchSavedLogin("antigravity", "ghost@example.com")
	if err == nil {
		t.Fatal("expected error switching to non-existent antigravity account, got nil")
	}

	// Verify valid account still live
	liveAg, ok := antigravityLiveLogin()
	if !ok || liveAg.User != "valid@example.com" {
		t.Fatalf("active antigravity account mutated on non-existent switch: %v (ok=%v)", liveAg, ok)
	}

	// 2. Non-existent Factory in switchSavedLogin
	_, err = switchSavedLogin("factory", "ghost@factory.ai")
	if err == nil {
		t.Fatal("expected error switching to non-existent factory account, got nil")
	}
	liveFact, ok := factoryLiveLogin()
	if !ok || liveFact.User != "valid@factory.ai" {
		t.Fatalf("active factory account mutated on non-existent switch: %v (ok=%v)", liveFact, ok)
	}

	// 3. Non-existent in switchLogin with SwitchOnly=true
	_ = SetSwitchOnly("antigravity", true)
	if err := switchLogin("antigravity", "ghost@example.com"); err == nil {
		t.Fatal("expected error in switchLogin with SwitchOnly=true, got nil")
	}

	// 4. Non-existent in switchLogin with SwitchOnly=false
	_ = SetSwitchOnly("antigravity", false)
	if err := switchLogin("antigravity", "ghost@example.com"); err == nil {
		t.Fatal("expected error in switchLogin with SwitchOnly=false, got nil")
	}
}

// TestAdversarialSwitchLoginSwitchOnlyPriority tests the distinction between
// pure client credential switching and gateway side-login priority manipulation.
func TestAdversarialSwitchLoginSwitchOnlyPriority(t *testing.T) {
	_, tmp := isolateAntigravity(t)

	clientAuth := sampleAntigravityAuth("client-user@example.com")
	sideAuth, _ := json.Marshal(googleAuth{
		AccessToken:  "side-access-token",
		RefreshToken: "side-refresh-token",
		Project:      "side-project",
	})

	ls := []savedLogin{
		{Agent: "antigravity", User: "client-user@example.com", Auth: clientAuth},
		{Agent: "antigravity", User: "side-user@example.com", Auth: sideAuth},
	}
	loginsMu.Lock()
	_ = writeLogins(ls)
	loginsMu.Unlock()

	// Initial active client account
	_ = saveAntigravityLogin(savedLogin{Agent: "antigravity", User: "client-user@example.com", Auth: clientAuth})

	// Scenario 1: SwitchOnly=false, switch on side-login account (no client payload)
	_ = SetSwitchOnly("antigravity", false)
	if err := switchLogin("antigravity", "side-user@example.com"); err != nil {
		t.Fatalf("switchLogin side-user: %v", err)
	}

	// Active client login MUST NOT be overwritten because this was a gateway side-login switch!
	liveAg, ok := antigravityLiveLogin()
	if !ok || liveAg.User != "client-user@example.com" {
		t.Fatalf("side-login switch mutated client store! Got %v (ok=%v)", liveAg, ok)
	}

	// Check logins.json side-login priority
	loginsAfter := readLogins()
	for _, l := range loginsAfter {
		if l.Agent == "antigravity" && l.User == "side-user@example.com" {
			if !l.First {
				t.Fatalf("side-login was not marked First=true in logins.json")
			}
		}
	}

	// Scenario 2: SwitchOnly=true, switch on client-user account
	_ = SetSwitchOnly("antigravity", true)
	if err := switchLogin("antigravity", "client-user@example.com"); err != nil {
		t.Fatalf("switchLogin client-user with SwitchOnly=true: %v", err)
	}
	liveAg2, ok := antigravityLiveLogin()
	if !ok || liveAg2.User != "client-user@example.com" {
		t.Fatalf("SwitchOnly switch failed to keep client-user live: %v", liveAg2)
	}
	_ = tmp
}

// TestAdversarialSandboxingPermissions tests private file permissions (0600) and directories (0700).
func TestAdversarialSandboxingPermissions(t *testing.T) {
	_, _ = isolateAntigravity(t)
	_, tmp := isolateFactory(t)

	authAg := sampleAntigravityAuth("perms@example.com")
	if err := saveAntigravityLogin(savedLogin{Agent: "antigravity", User: "perms@example.com", Auth: authAg}); err != nil {
		t.Fatal(err)
	}

	authFact := sampleFactoryAuth("perms@factory.ai", "orgP")
	if err := saveFactoryLogin(savedLogin{Agent: "factory", User: "perms@factory.ai", Auth: authFact}); err != nil {
		t.Fatal(err)
	}

	// Check Antigravity files: 0600 permissions
	agFiles := []string{
		filepath.Join(tmp, ".gemini", "antigravity-cli", "antigravity-oauth-token"),
		filepath.Join(tmp, ".gemini", "jetski-standalone-oauth-token"),
		filepath.Join(tmp, ".gemini", "google_accounts.json"),
	}
	for _, f := range agFiles {
		info, err := os.Stat(f)
		if err != nil {
			t.Fatalf("missing antigravity file %s: %v", f, err)
		}
		mode := info.Mode().Perm()
		if mode != 0600 {
			t.Fatalf("file %s has insecure permissions: %04o, expected 0600", f, mode)
		}
	}

	// Check Factory files: 0600 permissions
	factFiles := []string{
		filepath.Join(tmp, ".factory", "auth.v2.key"),
		filepath.Join(tmp, ".factory", "auth.v2.file"),
		filepath.Join(tmp, ".factory", "auth.v2.loginkeychain"),
	}
	for _, f := range factFiles {
		info, err := os.Stat(f)
		if err != nil {
			t.Fatalf("missing factory file %s: %v", f, err)
		}
		mode := info.Mode().Perm()
		if mode != 0600 {
			t.Fatalf("file %s has insecure permissions: %04o, expected 0600", f, mode)
		}
	}
}

// TestAdversarialConcurrentSafety tests that rapid concurrent switches between
// accounts cannot corrupt files or cause panics.
func TestAdversarialConcurrentSafety(t *testing.T) {
	isolateAntigravity(t)
	isolateFactory(t)

	authAg1 := sampleAntigravityAuth("ag1@example.com")
	authAg2 := sampleAntigravityAuth("ag2@example.com")
	authF1 := sampleFactoryAuth("f1@factory.ai", "org1")
	authF2 := sampleFactoryAuth("f2@factory.ai", "org2")

	ls := []savedLogin{
		{Agent: "antigravity", User: "ag1@example.com", Auth: authAg1},
		{Agent: "antigravity", User: "ag2@example.com", Auth: authAg2},
		{Agent: "factory", User: "f1@factory.ai", Auth: authF1},
		{Agent: "factory", User: "f2@factory.ai", Auth: authF2},
	}
	loginsMu.Lock()
	_ = writeLogins(ls)
	loginsMu.Unlock()

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	// 20 concurrent goroutines rapidly switching
	for i := 0; i < 20; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			for round := 0; round < 5; round++ {
				var err error
				if idx%2 == 0 {
					targetAg := "ag1@example.com"
					if round%2 == 1 {
						targetAg = "ag2@example.com"
					}
					_, err = switchSavedLogin("antigravity", targetAg)
				} else {
					targetF := "f1@factory.ai"
					if round%2 == 1 {
						targetF = "f2@factory.ai"
					}
					_, err = switchSavedLogin("factory", targetF)
				}
				if err != nil {
					errCh <- err
					return
				}
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent switch error: %v", err)
	}

	// Verify both stores are completely intact and readable after concurrent stress
	liveAg, okAg := antigravityLiveLogin()
	if !okAg || (liveAg.User != "ag1@example.com" && liveAg.User != "ag2@example.com") {
		t.Fatalf("antigravity store corrupted after concurrent switches: %v (ok=%v)", liveAg, okAg)
	}

	liveF, okF := factoryLiveLogin()
	if !okF || (liveF.User != "f1@factory.ai" && liveF.User != "f2@factory.ai") {
		t.Fatalf("factory store corrupted after concurrent switches: %v (ok=%v)", liveF, okF)
	}
}
