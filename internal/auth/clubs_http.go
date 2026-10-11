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
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"-"`
}

type clubCreated struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

type profileResponse struct {
	ID                        string        `json:"id"`
	Login                     string        `json:"login"`
	GlobalRole                string        `json:"global_role"`
	Clubs                     []clubSummary `json:"clubs"`
	AdministratorClubIDs      []string      `json:"administrator_club_ids"`
	PendingApplicationClubIDs []string      `json:"pending_application_club_ids"`
	nextCursor                string        `json:"-"`
}

type profileClubState struct {
	Club       clubSummary
	IsMember   bool
	IsAdmin    bool
	HasPending bool
}

func (h *HTTPHandler) clubs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listClubs(w, r)
	case http.MethodPost:
		if r.URL.RawQuery != "" {
			writeError(w, http.StatusBadRequest, "query parameters are not supported")
			return
		}
		h.createClub(w, r)
	default:
		methodNotAllowed(w, "GET, POST")
	}
}

func (h *HTTPHandler) listClubs(w http.ResponseWriter, r *http.Request) {
	page, err := parsePaginationQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid pagination parameters")
		return
	}
	clubs, err := readActiveClubs(r.Context(), h.service.db, page)
	if err != nil {
		if errors.Is(err, errInvalidPagination) {
			writeError(w, http.StatusBadRequest, "invalid pagination parameters")
			return
		}
		writeError(w, http.StatusInternalServerError, "request failed")
		return
	}
	writePage(w, clubs)
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
	if !decodeJSONWithLimit(w, r, &input, maxTextRequestBody) {
		return
	}
	if strings.TrimSpace(input.Name) == "" || !textWithinLimit(input.Name, maxClubNameLength) || !textWithinLimit(input.Description, maxTextLength) {
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
	page, err := parsePaginationQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid pagination parameters")
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
	profile, err := readProfile(r.Context(), h.service.db, principal.UserID, page)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusUnauthorized, "authentication required")
		} else {
			writeError(w, http.StatusInternalServerError, "request failed")
		}
		return
	}
	if profile.nextCursor != "" {
		w.Header().Set("X-Next-Cursor", profile.nextCursor)
	}
	writeJSON(w, profile)
}

func readActiveClubs(ctx context.Context, db *sql.DB, page pageRequest) (pageResult[clubSummary], error) {
	cursorTime, err := parseTimeCursor(page.Cursor)
	if err != nil {
		return pageResult[clubSummary]{}, err
	}
	var cursorID any
	if page.Cursor != nil {
		cursorID = page.Cursor.ID
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id::text, name, description, created_at
		FROM clubs
		WHERE status = 'active'
		  AND ($1::timestamptz IS NULL OR created_at < $1 OR (created_at = $1 AND id > $2::uuid))
		ORDER BY created_at DESC, id ASC
		LIMIT $3`, nullableTime(page.Cursor, cursorTime), cursorID, page.Limit+1)
	if err != nil {
		return pageResult[clubSummary]{}, err
	}
	defer rows.Close()
	clubs := make([]clubSummary, 0)
	for rows.Next() {
		var club clubSummary
		if err := rows.Scan(&club.ID, &club.Name, &club.Description, &club.CreatedAt); err != nil {
			return pageResult[clubSummary]{}, err
		}
		clubs = append(clubs, club)
	}
	if err := rows.Err(); err != nil {
		return pageResult[clubSummary]{}, err
	}
	return finishPage(clubs, page.Limit, func(club clubSummary) pageCursor {
		return pageCursor{Key: club.CreatedAt.Format(time.RFC3339Nano), ID: club.ID}
	}), nil
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

func readProfile(ctx context.Context, db *sql.DB, userID string, page pageRequest) (profileResponse, error) {
	var profile profileResponse
	if err := db.QueryRowContext(ctx,
		"SELECT id::text, login, global_role FROM users WHERE id = $1", userID,
	).Scan(&profile.ID, &profile.Login, &profile.GlobalRole); err != nil {
		return profileResponse{}, err
	}
	cursorTime, err := parseTimeCursor(page.Cursor)
	if err != nil {
		return profileResponse{}, err
	}
	var cursorID any
	if page.Cursor != nil {
		cursorID = page.Cursor.ID
	}
	rows, err := db.QueryContext(ctx, `
		SELECT clubs.id::text, clubs.name, clubs.description, clubs.created_at,
		       memberships.user_id IS NOT NULL,
		       administrators.user_id IS NOT NULL,
		       pending.id IS NOT NULL
		FROM clubs
		LEFT JOIN club_memberships AS memberships
		  ON memberships.club_id = clubs.id AND memberships.user_id = $1
		LEFT JOIN club_administrators AS administrators
		  ON administrators.club_id = clubs.id AND administrators.user_id = $1
		LEFT JOIN applications AS pending
		  ON pending.club_id = clubs.id AND pending.user_id = $1 AND pending.status = 'pending'
		WHERE clubs.status = 'active'
		  AND (memberships.user_id IS NOT NULL OR administrators.user_id IS NOT NULL OR pending.id IS NOT NULL)
		  AND ($2::timestamptz IS NULL OR clubs.created_at < $2 OR (clubs.created_at = $2 AND clubs.id > $3::uuid))
		ORDER BY clubs.created_at DESC, clubs.id ASC
		LIMIT $4`, userID, nullableTime(page.Cursor, cursorTime), cursorID, page.Limit+1)
	if err != nil {
		return profileResponse{}, err
	}
	defer rows.Close()
	states := make([]profileClubState, 0)
	for rows.Next() {
		var state profileClubState
		if err := rows.Scan(&state.Club.ID, &state.Club.Name, &state.Club.Description, &state.Club.CreatedAt,
			&state.IsMember, &state.IsAdmin, &state.HasPending); err != nil {
			return profileResponse{}, err
		}
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return profileResponse{}, err
	}
	pageResult := finishPage(states, page.Limit, func(state profileClubState) pageCursor {
		return pageCursor{Key: state.Club.CreatedAt.Format(time.RFC3339Nano), ID: state.Club.ID}
	})
	profile.Clubs = make([]clubSummary, 0, len(pageResult.Items))
	profile.AdministratorClubIDs = make([]string, 0)
	profile.PendingApplicationClubIDs = make([]string, 0)
	for _, state := range pageResult.Items {
		if state.IsMember {
			profile.Clubs = append(profile.Clubs, state.Club)
		}
		if state.IsAdmin {
			profile.AdministratorClubIDs = append(profile.AdministratorClubIDs, state.Club.ID)
		}
		if state.HasPending {
			profile.PendingApplicationClubIDs = append(profile.PendingApplicationClubIDs, state.Club.ID)
		}
	}
	profile.nextCursor = pageResult.NextCursor
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
