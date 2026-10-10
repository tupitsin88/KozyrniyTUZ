package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tupitsin88/KozyrniyTUZ/internal/config"
)

const sessionBootstrapLockID int64 = 7319460281542

var ErrInvalidCredentials = errors.New("invalid login or password")
var ErrLoginExists = errors.New("login already exists")
var ErrInvalidInput = errors.New("invalid input")
var ErrSessionInvalid = errors.New("session is not valid")

type Service struct {
	db              *sql.DB
	trustedOrigin   string
	cookieName      string
	cookieSecure    bool
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
	argon           argonParameters
	dummyVerifier   string
}

type Principal struct {
	UserID string
	Role   string
	CSRF   []byte
	Hash   []byte
}

func NewService(db *sql.DB, settings config.Config) (*Service, error) {
	service := &Service{
		db:              db,
		trustedOrigin:   settings.TrustedOrigin,
		cookieName:      "club-session",
		cookieSecure:    strings.HasPrefix(settings.TrustedOrigin, "https://"),
		idleTimeout:     settings.SessionIdle,
		absoluteTimeout: settings.SessionAbsolute,
		argon: argonParameters{
			memory: settings.ArgonMemory, iterations: settings.ArgonIterations, parallel: settings.ArgonParallelism,
		},
	}
	if service.cookieSecure {
		service.cookieName = "__Host-session"
	}
	dummy, err := hashPassword("unusable-dummy-secret", service.argon)
	if err != nil {
		return nil, fmt.Errorf("initialize password verifier")
	}
	service.dummyVerifier = dummy
	return service, nil
}

func (s *Service) Bootstrap(ctx context.Context, login, password string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin SuperUser bootstrap")
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", sessionBootstrapLockID); err != nil {
		return fmt.Errorf("lock SuperUser bootstrap")
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM users WHERE global_role = 'SuperUser'").Scan(&count); err != nil {
		return fmt.Errorf("read SuperUser count")
	}
	switch count {
	case 0:
		if login == "" || password == "" {
			return fmt.Errorf("BOOTSTRAP_SUPERUSER_LOGIN and BOOTSTRAP_SUPERUSER_PASSWORD are required when no SuperUser exists")
		}
		normalizedLogin, err := normalizeLogin(login)
		if err != nil {
			return fmt.Errorf("BOOTSTRAP_SUPERUSER_LOGIN is invalid")
		}
		if err := validatePassword(password); err != nil {
			return fmt.Errorf("BOOTSTRAP_SUPERUSER_PASSWORD is invalid")
		}
		verifier, err := hashPassword(password, s.argon)
		if err != nil {
			return fmt.Errorf("create SuperUser password verifier")
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO users (login, password_verifier, global_role) VALUES ($1, $2, 'SuperUser')",
			normalizedLogin, verifier,
		); err != nil {
			return fmt.Errorf("create SuperUser account")
		}
	case 1:
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("finish SuperUser bootstrap check")
		}
		return nil
	default:
		return fmt.Errorf("database integrity error: expected one SuperUser, found %d", count)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit SuperUser bootstrap")
	}
	return nil
}

func (s *Service) Register(ctx context.Context, login, password, oldToken string) (string, []byte, []byte, error) {
	normalizedLogin, err := normalizeLogin(login)
	if err != nil || validatePassword(password) != nil {
		return "", nil, nil, ErrInvalidInput
	}
	verifier, err := hashPassword(password, s.argon)
	if err != nil {
		return "", nil, nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", nil, nil, fmt.Errorf("begin account registration")
	}
	defer func() { _ = tx.Rollback() }()
	var userID string
	err = tx.QueryRowContext(ctx,
		"INSERT INTO users (login, password_verifier, global_role) VALUES ($1, $2, 'User') RETURNING id::text",
		normalizedLogin, verifier,
	).Scan(&userID)
	if err != nil {
		if isUniqueViolation(err) {
			return "", nil, nil, ErrLoginExists
		}
		return "", nil, nil, fmt.Errorf("create account")
	}
	raw, csrf, err := s.createSession(ctx, tx, userID, oldToken)
	if err != nil {
		return "", nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return "", nil, nil, fmt.Errorf("commit account registration")
	}
	return userID, raw, csrf, nil
}

func (s *Service) Login(ctx context.Context, login, password, oldToken string) (string, []byte, []byte, error) {
	normalizedLogin, err := normalizeLogin(login)
	if err != nil || validatePassword(password) != nil {
		_, _, verifyErr := verifyPassword(s.dummyVerifier, password)
		if verifyErr != nil {
			return "", nil, nil, verifyErr
		}
		return "", nil, nil, ErrInvalidCredentials
	}
	var userID, verifier string
	err = s.db.QueryRowContext(ctx,
		"SELECT id::text, password_verifier FROM users WHERE login = $1", normalizedLogin,
	).Scan(&userID, &verifier)
	if err == sql.ErrNoRows {
		verifier = s.dummyVerifier
	} else if err != nil {
		return "", nil, nil, fmt.Errorf("read account for login")
	}
	valid, stored, verifyErr := verifyPassword(verifier, password)
	if verifyErr != nil || err == sql.ErrNoRows || !valid {
		return "", nil, nil, ErrInvalidCredentials
	}
	var upgraded string
	if needsRehash(*stored, s.argon) {
		upgraded, err = hashPassword(password, upgradeParameters(*stored, s.argon))
		if err != nil {
			return "", nil, nil, fmt.Errorf("upgrade password verifier")
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", nil, nil, fmt.Errorf("begin login session")
	}
	defer func() { _ = tx.Rollback() }()
	if upgraded != "" {
		result, err := tx.ExecContext(ctx, "UPDATE users SET password_verifier = $1 WHERE id = $2 AND password_verifier = $3", upgraded, userID, verifier)
		if err != nil {
			return "", nil, nil, fmt.Errorf("upgrade account password verifier")
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return "", nil, nil, fmt.Errorf("account password verifier changed during login")
		}
		if changed == 0 {
			var currentVerifier string
			if err := tx.QueryRowContext(ctx, "SELECT password_verifier FROM users WHERE id = $1 FOR UPDATE", userID).Scan(&currentVerifier); err != nil {
				return "", nil, nil, fmt.Errorf("read current account password verifier")
			}
			validCurrent, _, err := verifyPassword(currentVerifier, password)
			if err != nil || !validCurrent {
				return "", nil, nil, ErrInvalidCredentials
			}
		}
		if changed > 1 {
			return "", nil, nil, fmt.Errorf("unexpected account update count")
		}
	}
	raw, csrf, err := s.createSession(ctx, tx, userID, oldToken)
	if err != nil {
		return "", nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return "", nil, nil, fmt.Errorf("commit login session")
	}
	return userID, raw, csrf, nil
}

func (s *Service) createSession(ctx context.Context, tx *sql.Tx, userID, oldToken string) ([]byte, []byte, error) {
	if oldToken != "" {
		if oldRaw, err := base64.RawURLEncoding.DecodeString(oldToken); err == nil && len(oldRaw) == 32 {
			oldHash := sha256.Sum256(oldRaw)
			if _, err := tx.ExecContext(ctx, "UPDATE user_sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now() AND last_seen_at > now() - $2::interval", oldHash[:], s.idleTimeout.String()); err != nil {
				return nil, nil, fmt.Errorf("revoke replaced session")
			}
		}
	}
	raw := make([]byte, 32)
	csrf := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, nil, fmt.Errorf("generate session token")
	}
	if _, err := rand.Read(csrf); err != nil {
		return nil, nil, fmt.Errorf("generate CSRF token")
	}
	hash := sha256.Sum256(raw)
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO user_sessions (token_hash, csrf_token, user_id, expires_at) VALUES ($1, $2, $3, now() + $4::interval)",
		hash[:], csrf, userID, s.absoluteTimeout.String(),
	); err != nil {
		return nil, nil, fmt.Errorf("create server session")
	}
	return raw, csrf, nil
}

func (s *Service) Authenticate(ctx context.Context, token string) (Principal, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return Principal{}, ErrSessionInvalid
	}
	hash := sha256.Sum256(raw)
	var principal Principal
	err = s.db.QueryRowContext(ctx, `
		SELECT users.id::text, users.global_role, sessions.csrf_token
		FROM user_sessions AS sessions
		JOIN users ON users.id = sessions.user_id
		WHERE sessions.token_hash = $1
		  AND sessions.revoked_at IS NULL
		  AND sessions.expires_at > now()
		  AND sessions.last_seen_at > now() - $2::interval`, hash[:], s.idleTimeout.String(),
	).Scan(&principal.UserID, &principal.Role, &principal.CSRF)
	if err != nil {
		if err == sql.ErrNoRows {
			return Principal{}, ErrSessionInvalid
		}
		return Principal{}, fmt.Errorf("validate server session")
	}
	principal.Hash = hash[:]
	return principal, nil
}

func (s *Service) Touch(ctx context.Context, principal Principal) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE user_sessions
		SET last_seen_at = now()
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		  AND expires_at > now()
		  AND last_seen_at > now() - $2::interval`, principal.Hash, s.idleTimeout.String())
	if err != nil {
		return fmt.Errorf("update server session activity")
	}
	updated, err := result.RowsAffected()
	if err != nil || updated != 1 {
		return ErrSessionInvalid
	}
	return nil
}

func (s *Service) Revoke(ctx context.Context, principal Principal) error {
	_, err := s.db.ExecContext(ctx, "UPDATE user_sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL", principal.Hash)
	if err != nil {
		return fmt.Errorf("revoke server session")
	}
	return nil
}

func (s *Service) TrustedOrigin() string { return s.trustedOrigin }
func (s *Service) CookieName() string    { return s.cookieName }
func (s *Service) CookieSecure() bool    { return s.cookieSecure }

func normalizeLogin(login string) (string, error) {
	if len(login) < 3 || len(login) > 64 {
		return "", ErrInvalidInput
	}
	for _, char := range login {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') && char != '.' && char != '_' && char != '-' {
			return "", ErrInvalidInput
		}
	}
	return strings.ToLower(login), nil
}

func validatePassword(password string) error {
	if len(password) < 12 || len(password) > 1024 {
		return ErrInvalidInput
	}
	return nil
}

func isUniqueViolation(err error) bool {
	type sqlState interface{ SQLState() string }
	var state sqlState
	return errors.As(err, &state) && state.SQLState() == "23505"
}
