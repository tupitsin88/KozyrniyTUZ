package auth

import (
	"strings"
	"testing"
)

func TestHashPasswordUsesUniqueArgon2idSalt(t *testing.T) {
	params := argonParameters{memory: 19 * 1024, iterations: 2, parallel: 1}
	first, err := hashPassword("correct horse battery staple", params)
	if err != nil {
		t.Fatal(err)
	}
	second, err := hashPassword("correct horse battery staple", params)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("equal passwords produced identical verifiers")
	}
	if !strings.HasPrefix(first, "v=1$argon2id$m=19456,t=2,p=1$") {
		t.Fatalf("verifier does not contain the configured Argon2id parameters: %q", first)
	}
	valid, _, err := verifyPassword(first, "correct horse battery staple")
	if err != nil || !valid {
		t.Fatalf("correct password was rejected: valid=%v err=%v", valid, err)
	}
	valid, _, err = verifyPassword(first, "a different password")
	if err != nil || valid {
		t.Fatalf("incorrect password was accepted: valid=%v err=%v", valid, err)
	}
}

func TestVerifyPasswordRejectsUnsupportedOrUnsafeVerifier(t *testing.T) {
	cases := []string{
		"v=2$argon2id$m=19456,t=2,p=1$c2FsdA$cmVzdWx0",
		"v=1$scrypt$m=19456,t=2,p=1$c2FsdA$cmVzdWx0",
		"v=1$argon2id$m=1,t=1,p=1$c2FsdA$cmVzdWx0",
		"v=1$argon2id$m=999999,t=99,p=99$c2FsdA$cmVzdWx0",
		"v=1$argon2id$m=x,t=2,p=1$c2FsdA$cmVzdWx0",
	}
	for _, verifier := range cases {
		t.Run(verifier, func(t *testing.T) {
			if _, _, err := verifyPassword(verifier, "some password"); err == nil {
				t.Fatal("invalid verifier was accepted")
			}
		})
	}
	if _, _, err := verifyPassword(strings.Repeat("x", 257), "some password"); err == nil {
		t.Fatal("oversized verifier was accepted")
	}
}

func TestNormalizeLoginAndValidatePassword(t *testing.T) {
	login, err := normalizeLogin("User.Name_01")
	if err != nil || login != "user.name_01" {
		t.Fatalf("normalizeLogin() = %q, %v", login, err)
	}
	for _, login := range []string{"ab", "contains space", "has/slash", "другой"} {
		if _, err := normalizeLogin(login); err == nil {
			t.Errorf("normalizeLogin(%q) accepted invalid login", login)
		}
	}
	if err := validatePassword("short"); err == nil {
		t.Fatal("short password was accepted")
	}
	if err := validatePassword(strings.Repeat("p", 1025)); err == nil {
		t.Fatal("oversized password was accepted")
	}
	if err := validatePassword("correct horse battery staple"); err != nil {
		t.Fatalf("valid password was rejected: %v", err)
	}
}

func TestUpgradeParametersNeverReduceAnExistingParameter(t *testing.T) {
	stored := argonParameters{memory: 64 * 1024, iterations: 2, parallel: 1}
	current := argonParameters{memory: 19 * 1024, iterations: 3, parallel: 2}
	if got, want := upgradeParameters(stored, current), (argonParameters{memory: 64 * 1024, iterations: 3, parallel: 2}); got != want {
		t.Fatalf("upgradeParameters() = %#v, want %#v", got, want)
	}
}
