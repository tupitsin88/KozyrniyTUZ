package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tupitsin88/KozyrniyTUZ/internal/config"
	"github.com/tupitsin88/KozyrniyTUZ/internal/database"
)

func TestPostgresAuthenticationLifecycle(t *testing.T) {
	baseURL := os.Getenv("AUTH_TEST_DATABASE_URL")
	if baseURL == "" {
		t.Skip("AUTH_TEST_DATABASE_URL is not set")
	}

	adminDB, err := sql.Open("pgx", baseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer adminDB.Close()
	schema := fmt.Sprintf("auth_test_%d", time.Now().UnixNano())
	if _, err := adminDB.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = adminDB.Exec("DROP SCHEMA " + schema + " CASCADE")
	})
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsedURL.Query()
	query.Set("search_path", schema)
	parsedURL.RawQuery = query.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := database.Open(ctx, parsedURL.String(), database.PoolConfig{
		MaxOpenConns: 5, MaxIdleConns: 2, ConnMaxLifetime: time.Minute, ConnMaxIdleTime: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	settings := config.Config{
		TrustedOrigin: "http://localhost:8080", SessionIdle: 30 * time.Minute, SessionAbsolute: 12 * time.Hour,
		ArgonMemory: 19 * 1024, ArgonIterations: 2, ArgonParallelism: 1,
	}
	service, err := NewService(db, settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Bootstrap(ctx, "", ""); err == nil {
		t.Fatal("bootstrap without credentials succeeded on an empty database")
	}
	if err := service.Bootstrap(ctx, "Root.Admin", "bootstrap secret with enough length"); err != nil {
		t.Fatal(err)
	}
	if err := service.Bootstrap(ctx, "ignored", "ignored password long enough"); err != nil {
		t.Fatal(err)
	}
	var superCount int
	var rootVerifier string
	if err := db.QueryRowContext(ctx, "SELECT count(*), min(password_verifier) FROM users WHERE global_role = 'SuperUser'").Scan(&superCount, &rootVerifier); err != nil {
		t.Fatal(err)
	}
	if superCount != 1 || rootVerifier == "bootstrap secret with enough length" {
		t.Fatalf("bootstrap state is unsafe: count=%d verifier=%q", superCount, rootVerifier)
	}

	login := fmt.Sprintf("user%d", time.Now().UnixNano())
	password := "correct horse battery staple"
	userID, raw, csrf, err := service.Register(ctx, login, password, "")
	if err != nil {
		t.Fatal(err)
	}
	var role, verifier string
	if err := db.QueryRowContext(ctx, "SELECT global_role, password_verifier FROM users WHERE id = $1", userID).Scan(&role, &verifier); err != nil {
		t.Fatal(err)
	}
	if role != "User" || verifier == password || !strings.HasPrefix(verifier, "v=1$argon2id$") {
		t.Fatalf("registration created unsafe account state: role=%q verifier=%q", role, verifier)
	}
	initialHash := sha256.Sum256(raw)
	var storedTokenHash []byte
	if err := db.QueryRowContext(ctx, "SELECT token_hash FROM user_sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1", userID).Scan(&storedTokenHash); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(storedTokenHash, raw) || !bytes.Equal(storedTokenHash, initialHash[:]) {
		t.Fatal("database did not retain only the SHA-256 session token fingerprint")
	}
	if _, _, _, err := service.Register(ctx, login, password, ""); !errors.Is(err, ErrLoginExists) {
		t.Fatalf("duplicate login error = %v, want ErrLoginExists", err)
	}

	oldToken := base64Token(raw)
	if _, _, _, err := service.Login(ctx, login, "wrong password value", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password error = %v", err)
	}
	if _, _, _, err := service.Login(ctx, login+"missing", password, ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown login error = %v", err)
	}
	_, rotatedRaw, rotatedCSRF, err := service.Login(ctx, strings.ToUpper(login), password, oldToken)
	if err != nil {
		t.Fatal(err)
	}
	if oldToken == base64Token(rotatedRaw) || string(csrf) == string(rotatedCSRF) {
		t.Fatal("login reused a session token or CSRF token")
	}
	if _, err := service.Authenticate(ctx, oldToken); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("replaced session remained valid: %v", err)
	}
	principal, err := service.Authenticate(ctx, base64Token(rotatedRaw))
	if err != nil {
		t.Fatal(err)
	}
	if principal.UserID != userID || principal.Role != "User" || string(principal.CSRF) != string(rotatedCSRF) {
		t.Fatalf("authenticated principal = %#v", principal)
	}
	if err := service.Touch(ctx, principal); err != nil {
		t.Fatal(err)
	}
	if err := service.Revoke(ctx, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, base64Token(rotatedRaw)); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("revoked session remained valid: %v", err)
	}

	legacyVerifier, err := hashPassword(password, argonParameters{memory: 19 * 1024, iterations: 2, parallel: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE users SET password_verifier = $1 WHERE id = $2", legacyVerifier, userID); err != nil {
		t.Fatal(err)
	}
	upgradingSettings := settings
	upgradingSettings.ArgonParallelism = 2
	upgradingService, err := NewService(db, upgradingSettings)
	if err != nil {
		t.Fatal(err)
	}
	_, upgradedRaw, _, err := upgradingService.Login(ctx, login, password, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT password_verifier FROM users WHERE id = $1", userID).Scan(&verifier); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(verifier, "v=1$argon2id$m=19456,t=2,p=2$") {
		t.Fatalf("successful login did not upgrade Argon2id parameters: %q", verifier)
	}
	if _, err := upgradingService.Authenticate(ctx, base64Token(upgradedRaw)); err != nil {
		t.Fatalf("upgraded login session is not valid: %v", err)
	}

	_, idleRaw, _, err := upgradingService.Login(ctx, login, password, "")
	if err != nil {
		t.Fatal(err)
	}
	idleHash := sha256.Sum256(idleRaw)
	if _, err := db.ExecContext(ctx, `
		UPDATE user_sessions
		SET created_at = now() - interval '32 minutes',
		    last_seen_at = now() - interval '31 minutes'
		WHERE token_hash = $1`, idleHash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := upgradingService.Authenticate(ctx, base64Token(idleRaw)); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("idle-expired session remained valid: %v", err)
	}

	_, absoluteRaw, _, err := upgradingService.Login(ctx, login, password, "")
	if err != nil {
		t.Fatal(err)
	}
	absoluteHash := sha256.Sum256(absoluteRaw)
	if _, err := db.ExecContext(ctx, `
		UPDATE user_sessions
		SET created_at = now() - interval '13 hours',
		    last_seen_at = now() - interval '12 hours 59 minutes 59 seconds',
		    expires_at = now() - interval '1 hour'
		WHERE token_hash = $1`, absoluteHash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := upgradingService.Authenticate(ctx, base64Token(absoluteRaw)); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("absolute-expired session remained valid: %v", err)
	}
}

func base64Token(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}
