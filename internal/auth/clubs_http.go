package auth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"
)

type clubInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type clubSummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type clubCreated struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

type profileResponse struct {
	ID                   string        `json:"id"`
	Login                string        `json:"login"`
	GlobalRole           string        `json:"global_role"`
	Clubs                []clubSummary `json:"clubs"`
	AdministratorClubIDs []string      `json:"administrator_club_ids"`
}

func (h *HTTPHandler) clubs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listClubs(w, r)
	case http.MethodPost:
		h.createClub(w, r)
	default:
		methodNotAllowed(w, "GET, POST")
	}
}

func (h *HTTPHandler) listClubs(w http.ResponseWriter, r *http.Request) {
	clubs, err := readActiveClubs(r.Context(), h.service.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "request failed")
		return
	}
	writeJSON(w, clubs)
}

func (h *HTTPHandler) createClub(w http.ResponseWriter, r *http.Request) {
	if !h.requireOrigin(w, r) || !requireJSON(w, r) {
		return
	}
	principal, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !csrfMatches(r.Header.Get("X-CSRF-Token"), principal.CSRF) {
		writeError(w, http.StatusForbidden, "CSRF validation failed")
		return
	}
	if principal.Role != "User" {
		writeError(w, http.StatusForbidden, "operation is not allowed")
		return
	}
	if err := h.service.Touch(r.Context(), principal); err != nil {
		writeSessionError(w, err)
		return
	}
	var input clubInput
	if !decodeJSON(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.Name) == "" {
		writeError(w, http.StatusBadRequest, "invalid club data")
		return
	}
	created, err := createClub(r.Context(), h.service.db, principal.UserID, input)
	if err != nil {
		var outcomeUnknown transactionOutcomeUnknownError
		if errors.As(err, &outcomeUnknown) {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]string{"error": "transaction outcome unknown", "code": "transaction_outcome_unknown"})
			return
		}
		writeError(w, http.StatusInternalServerError, "request failed")
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, created)
}

func (h *HTTPHandler) profile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if !allowSafeOrigin(w, r, h.service.TrustedOrigin()) {
		return
	}
	principal, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if err := h.service.Touch(r.Context(), principal); err != nil {
		writeSessionError(w, err)
		return
	}
	profile, err := readProfile(r.Context(), h.service.db, principal.UserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusUnauthorized, "authentication required")
		} else {
			writeError(w, http.StatusInternalServerError, "request failed")
		}
		return
	}
	writeJSON(w, profile)
}

func readActiveClubs(ctx context.Context, db *sql.DB) ([]clubSummary, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id::text, name, description
		FROM clubs
		WHERE status = 'active'
		ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	clubs := make([]clubSummary, 0)
	for rows.Next() {
		var club clubSummary
		if err := rows.Scan(&club.ID, &club.Name, &club.Description); err != nil {
			return nil, err
		}
		clubs = append(clubs, club)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return clubs, nil
}

func createClub(ctx context.Context, db *sql.DB, creatorID string, input clubInput) (clubCreated, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return clubCreated{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var created clubCreated
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO clubs (creator_id, name, description)
		VALUES ($1, $2, $3)
		RETURNING id::text, name, description, created_at`, creatorID, input.Name, input.Description,
	).Scan(&created.ID, &created.Name, &created.Description, &created.CreatedAt); err != nil {
		return clubCreated{}, err
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO club_administrators (user_id, club_id) VALUES ($1, $2)", creatorID, created.ID,
	); err != nil {
		return clubCreated{}, err
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO club_memberships (user_id, club_id) VALUES ($1, $2)", creatorID, created.ID,
	); err != nil {
		return clubCreated{}, err
	}
	if err := tx.Commit(); err != nil {
		return clubCreated{}, transactionOutcomeUnknownError{cause: err}
	}
	return created, nil
}

func readProfile(ctx context.Context, db *sql.DB, userID string) (profileResponse, error) {
	var profile profileResponse
	if err := db.QueryRowContext(ctx,
		"SELECT id::text, login, global_role FROM users WHERE id = $1", userID,
	).Scan(&profile.ID, &profile.Login, &profile.GlobalRole); err != nil {
		return profileResponse{}, err
	}
	rows, err := db.QueryContext(ctx, `
		SELECT clubs.id::text, clubs.name, clubs.description
		FROM club_memberships AS memberships
		JOIN clubs ON clubs.id = memberships.club_id
		WHERE memberships.user_id = $1
		  AND clubs.status = 'active'
		ORDER BY clubs.created_at DESC, clubs.id`, userID)
	if err != nil {
		return profileResponse{}, err
	}
	defer rows.Close()
	profile.Clubs = make([]clubSummary, 0)
	for rows.Next() {
		var club clubSummary
		if err := rows.Scan(&club.ID, &club.Name, &club.Description); err != nil {
			return profileResponse{}, err
		}
		profile.Clubs = append(profile.Clubs, club)
	}
	if err := rows.Err(); err != nil {
		return profileResponse{}, err
	}
	rows, err = db.QueryContext(ctx, `
		SELECT administrators.club_id::text
		FROM club_administrators AS administrators
		JOIN clubs ON clubs.id = administrators.club_id
		WHERE administrators.user_id = $1
		  AND clubs.status = 'active'
	ORDER BY administrators.club_id`, userID)
	if err != nil {
		return profileResponse{}, err
	}
	defer rows.Close()
	profile.AdministratorClubIDs = make([]string, 0)
	for rows.Next() {
		var clubID string
		if err := rows.Scan(&clubID); err != nil {
			return profileResponse{}, err
		}
		profile.AdministratorClubIDs = append(profile.AdministratorClubIDs, clubID)
	}
	if err := rows.Err(); err != nil {
		return profileResponse{}, err
	}
	return profile, nil
}

type transactionOutcomeUnknownError struct {
	cause error
}

func (e transactionOutcomeUnknownError) Error() string { return "transaction outcome is unknown" }
func (e transactionOutcomeUnknownError) Unwrap() error { return e.cause }

func writeSessionError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrSessionInvalid) {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	writeError(w, http.StatusInternalServerError, "request failed")
}
