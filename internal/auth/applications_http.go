package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxTransactionAttempts = 3

var errApplicationNotFound = errors.New("application not found")
var errApplicationForbidden = errors.New("operation is not allowed")
var errApplicationConflict = errors.New("application state conflict")
var errTransactionRetriesExhausted = errors.New("transaction retries exhausted")

type applicationInput struct {
	ClubID string `json:"club_id"`
	Text   string `json:"text"`
}

type applicationDecisionInput struct {
	Status string `json:"status"`
}

type applicationRecord struct {
	ID              string     `json:"id"`
	UserID          string     `json:"user_id"`
	ClubID          string     `json:"club_id"`
	Text            string     `json:"text"`
	Status          string     `json:"status"`
	CreatedAt       time.Time  `json:"created_at"`
	AdministratorID *string    `json:"administrator_id"`
	DecidedAt       *time.Time `json:"decided_at"`
}

type clubMemberInput struct {
	Login string `json:"login"`
}

type clubMemberRecord struct {
	UserID string `json:"user_id"`
	Login  string `json:"login"`
}

type rowScanner interface {
	Scan(...any) error
}

func (h *HTTPHandler) applications(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "query parameters are not supported")
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.listApplications(w, r)
	case http.MethodPost:
		h.submitApplication(w, r)
	default:
		methodNotAllowed(w, "GET, POST")
	}
}

func (h *HTTPHandler) application(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "query parameters are not supported")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/applications/")
	parts := strings.Split(path, "/")
	if len(parts) == 1 && isUUID(parts[0]) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		h.readApplication(w, r, parts[0])
		return
	}
	if len(parts) == 2 && isUUID(parts[0]) && parts[1] == "decision" {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		h.decideApplication(w, r, parts[0])
		return
	}
	http.NotFound(w, r)
}

func (h *HTTPHandler) listApplications(w http.ResponseWriter, r *http.Request) {
	page, err := parsePaginationQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid pagination parameters")
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
	applications, err := readApplications(r.Context(), h.service.db, principal.UserID, page)
	if err != nil {
		if errors.Is(err, errInvalidPagination) {
			writeError(w, http.StatusBadRequest, "invalid pagination parameters")
			return
		}
		writeApplicationError(w, err)
		return
	}
	writePage(w, applications)
}

func (h *HTTPHandler) readApplication(w http.ResponseWriter, r *http.Request, applicationID string) {
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "query parameters are not supported")
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
	application, err := readApplication(r.Context(), h.service.db, applicationID, principal.UserID)
	if err != nil {
		writeApplicationError(w, err)
		return
	}
	writeJSON(w, application)
}

func (h *HTTPHandler) submitApplication(w http.ResponseWriter, r *http.Request) {
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
		writeApplicationError(w, errApplicationForbidden)
		return
	}
	if err := h.service.Touch(r.Context(), principal); err != nil {
		writeSessionError(w, err)
		return
	}
	var input applicationInput
	if !decodeJSONWithLimit(w, r, &input, maxTextRequestBody) {
		return
	}
	if !isUUID(input.ClubID) || strings.TrimSpace(input.Text) == "" || !textWithinLimit(input.Text, maxTextLength) {
		writeApplicationError(w, ErrInvalidInput)
		return
	}
	application, err := createApplication(r.Context(), h.service.db, principal.UserID, input)
	if err != nil {
		writeApplicationError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, application)
}

func (h *HTTPHandler) decideApplication(w http.ResponseWriter, r *http.Request, applicationID string) {
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
	if err := h.service.Touch(r.Context(), principal); err != nil {
		writeSessionError(w, err)
		return
	}
	var input applicationDecisionInput
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Status != "approved" && input.Status != "rejected" {
		writeApplicationError(w, ErrInvalidInput)
		return
	}
	application, err := decideApplication(r.Context(), h.service.db, principal.UserID, applicationID, input.Status)
	if err != nil {
		writeApplicationError(w, err)
		return
	}
	writeJSON(w, application)
}

func (h *HTTPHandler) clubMemberships(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "query parameters are not supported")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/clubs/"), "/")
	if len(parts) != 3 || !isUUID(parts[0]) || parts[1] != "members" || !isUUID(parts[2]) {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodDelete {
		methodNotAllowed(w, "PUT, DELETE")
		return
	}
	if !h.requireOrigin(w, r) {
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
	if err := requireEmptyBody(w, r); err != nil {
		writeError(w, http.StatusBadRequest, "request body is not allowed")
		return
	}
	if err := h.service.Touch(r.Context(), principal); err != nil {
		writeSessionError(w, err)
		return
	}
	if err := changeMembership(r.Context(), h.service.db, principal.UserID, parts[0], parts[2], r.Method == http.MethodPut); err != nil {
		writeApplicationError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *HTTPHandler) clubMemberCollection(w http.ResponseWriter, r *http.Request, clubID string) {
	if r.Method != http.MethodGet && r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "query parameters are not supported")
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.listClubMembers(w, r, clubID)
	case http.MethodPost:
		h.addClubMemberByLogin(w, r, clubID)
	default:
		methodNotAllowed(w, "GET, POST")
	}
}

func (h *HTTPHandler) listClubMembers(w http.ResponseWriter, r *http.Request, clubID string) {
	page, err := parsePaginationQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid pagination parameters")
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
	members, err := readClubMembers(r.Context(), h.service.db, principal.UserID, clubID, page)
	if err != nil {
		if errors.Is(err, errInvalidPagination) {
			writeError(w, http.StatusBadRequest, "invalid pagination parameters")
			return
		}
		writeApplicationError(w, err)
		return
	}
	writePage(w, members)
}

func (h *HTTPHandler) addClubMemberByLogin(w http.ResponseWriter, r *http.Request, clubID string) {
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
	if err := h.service.Touch(r.Context(), principal); err != nil {
		writeSessionError(w, err)
		return
	}
	var input clubMemberInput
	if !decodeJSON(w, r, &input) {
		return
	}
	login, err := normalizeLogin(strings.TrimSpace(input.Login))
	if err != nil {
		writeApplicationError(w, ErrInvalidInput)
		return
	}
	if err := addClubMemberByLogin(r.Context(), h.service.db, principal.UserID, clubID, login); err != nil {
		writeApplicationError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func readClubMembers(ctx context.Context, db *sql.DB, actorID, clubID string, page pageRequest) (pageResult[clubMemberRecord], error) {
	var authorized bool
	if err := db.QueryRowContext(ctx, `
		SELECT EXISTS (
		    SELECT 1
		    FROM clubs
		    JOIN club_administrators AS administrators ON administrators.club_id = clubs.id
		    JOIN users ON users.id = administrators.user_id
		    WHERE clubs.id = $1 AND clubs.status = 'active'
		      AND administrators.user_id = $2 AND users.global_role = 'User'
		)`, clubID, actorID).Scan(&authorized); err != nil {
		return pageResult[clubMemberRecord]{}, err
	}
	if !authorized {
		return pageResult[clubMemberRecord]{}, errApplicationNotFound
	}
	var cursorKey, cursorID any
	if page.Cursor != nil {
		cursorKey, cursorID = page.Cursor.Key, page.Cursor.ID
	}
	rows, err := db.QueryContext(ctx, `
		SELECT memberships.user_id::text, users.login
		FROM club_memberships AS memberships
		JOIN users ON users.id = memberships.user_id
		JOIN clubs ON clubs.id = memberships.club_id
		WHERE memberships.club_id = $1
		  AND clubs.status = 'active'
		  AND EXISTS (
		      SELECT 1 FROM club_administrators AS administrators
		      JOIN users AS actors ON actors.id = administrators.user_id
		      WHERE administrators.user_id = $2
		        AND administrators.club_id = memberships.club_id
		        AND actors.global_role = 'User'
		  )
		  AND ($3::text IS NULL OR (users.login, memberships.user_id) > ($3::text, $4::uuid))
		ORDER BY users.login, memberships.user_id
		LIMIT $5`, clubID, actorID, cursorKey, cursorID, page.Limit+1)
	if err != nil {
		return pageResult[clubMemberRecord]{}, err
	}
	defer rows.Close()
	members := make([]clubMemberRecord, 0)
	for rows.Next() {
		var member clubMemberRecord
		if err := rows.Scan(&member.UserID, &member.Login); err != nil {
			return pageResult[clubMemberRecord]{}, err
		}
		members = append(members, member)
	}
	if err := rows.Err(); err != nil {
		return pageResult[clubMemberRecord]{}, err
	}
	return finishPage(members, page.Limit, func(member clubMemberRecord) pageCursor {
		return pageCursor{Key: member.Login, ID: member.UserID}
	}), nil
}

func addClubMemberByLogin(ctx context.Context, db *sql.DB, actorID, clubID, login string) error {
	return runReadCommitted(ctx, db, func(tx *sql.Tx) error {
		if err := lockActiveClub(tx, clubID); err != nil {
			return err
		}
		if err := lockAdministrator(tx, actorID, clubID, false); err != nil {
			return err
		}
		var userID string
		err := tx.QueryRowContext(ctx, "SELECT id::text FROM users WHERE login = $1", login).Scan(&userID)
		if errors.Is(err, sql.ErrNoRows) {
			return errApplicationNotFound
		}
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO club_memberships (user_id, club_id, created_at)
			VALUES ($1, $2, now()) ON CONFLICT (user_id, club_id) DO NOTHING`, userID, clubID)
		return err
	})
}

func readApplications(ctx context.Context, db *sql.DB, actorID string, page pageRequest) (pageResult[applicationRecord], error) {
	cursorTime, err := parseTimeCursor(page.Cursor)
	if err != nil {
		return pageResult[applicationRecord]{}, err
	}
	var cursorID any
	if page.Cursor != nil {
		cursorID = page.Cursor.ID
	}
	rows, err := db.QueryContext(ctx, `
		SELECT applications.id::text, applications.user_id::text, applications.club_id::text,
		       applications.text, applications.status, applications.created_at,
		       applications.administrator_id::text, applications.decided_at
		FROM applications
		JOIN clubs ON clubs.id = applications.club_id
		WHERE (applications.user_id = $1
		   OR (
		       (SELECT global_role FROM users WHERE id = $1) = 'User'
		       AND clubs.status = 'active'
		       AND EXISTS (
		           SELECT 1 FROM club_administrators AS administrators
		           WHERE administrators.user_id = $1
		             AND administrators.club_id = applications.club_id
		       )
		   ))
		  AND ($2::timestamptz IS NULL OR applications.created_at < $2 OR (applications.created_at = $2 AND applications.id > $3::uuid))
		ORDER BY applications.created_at DESC, applications.id ASC
		LIMIT $4`, actorID, nullableTime(page.Cursor, cursorTime), cursorID, page.Limit+1)
	if err != nil {
		return pageResult[applicationRecord]{}, err
	}
	defer rows.Close()
	applications := make([]applicationRecord, 0)
	for rows.Next() {
		application, err := scanApplication(rows)
		if err != nil {
			return pageResult[applicationRecord]{}, err
		}
		applications = append(applications, application)
	}
	if err := rows.Err(); err != nil {
		return pageResult[applicationRecord]{}, err
	}
	return finishPage(applications, page.Limit, func(application applicationRecord) pageCursor {
		return pageCursor{Key: application.CreatedAt.Format(time.RFC3339Nano), ID: application.ID}
	}), nil
}

func readApplication(ctx context.Context, db *sql.DB, applicationID, actorID string) (applicationRecord, error) {
	row := db.QueryRowContext(ctx, `
		SELECT applications.id::text, applications.user_id::text, applications.club_id::text,
		       applications.text, applications.status, applications.created_at,
		       applications.administrator_id::text, applications.decided_at
		FROM applications
		JOIN clubs ON clubs.id = applications.club_id
		WHERE applications.id = $1
		  AND (
		      applications.user_id = $2
		      OR (
		          (SELECT global_role FROM users WHERE id = $2) = 'User'
		          AND clubs.status = 'active'
		          AND EXISTS (
		              SELECT 1 FROM club_administrators AS administrators
		              WHERE administrators.user_id = $2
		                AND administrators.club_id = applications.club_id
		          )
		      )
		  )`, applicationID, actorID)
	application, err := scanApplication(row)
	if errors.Is(err, sql.ErrNoRows) {
		return applicationRecord{}, errApplicationNotFound
	}
	return application, err
}

func createApplication(ctx context.Context, db *sql.DB, actorID string, input applicationInput) (applicationRecord, error) {
	var created applicationRecord
	err := runReadCommitted(ctx, db, func(tx *sql.Tx) error {
		var clubStatus string
		err := tx.QueryRowContext(ctx, "SELECT status FROM clubs WHERE id = $1 FOR UPDATE", input.ClubID).Scan(&clubStatus)
		if errors.Is(err, sql.ErrNoRows) {
			return errApplicationNotFound
		}
		if err != nil {
			return err
		}
		if clubStatus != "active" {
			return errApplicationConflict
		}
		role, err := readGlobalRole(tx, actorID)
		if err != nil {
			return err
		}
		if role != "User" {
			return errApplicationForbidden
		}
		var memberExists, pendingExists bool
		if err := tx.QueryRowContext(ctx,
			"SELECT EXISTS (SELECT 1 FROM club_memberships WHERE user_id = $1 AND club_id = $2)", actorID, input.ClubID,
		).Scan(&memberExists); err != nil {
			return err
		}
		if memberExists {
			return errApplicationConflict
		}
		if err := tx.QueryRowContext(ctx,
			"SELECT EXISTS (SELECT 1 FROM applications WHERE user_id = $1 AND club_id = $2 AND status = 'pending')", actorID, input.ClubID,
		).Scan(&pendingExists); err != nil {
			return err
		}
		if pendingExists {
			return errApplicationConflict
		}
		created, err = scanApplication(tx.QueryRowContext(ctx, `
			INSERT INTO applications (user_id, club_id, text, status, created_at)
			VALUES ($1, $2, $3, 'pending', now())
			RETURNING id::text, user_id::text, club_id::text, text, status, created_at,
			          administrator_id::text, decided_at`, actorID, input.ClubID, input.Text))
		if isUniqueViolation(err) {
			return errApplicationConflict
		}
		return err
	})
	if err != nil {
		return applicationRecord{}, err
	}
	return created, nil
}

func decideApplication(ctx context.Context, db *sql.DB, actorID, applicationID, decision string) (applicationRecord, error) {
	var clubID string
	err := db.QueryRowContext(ctx, "SELECT club_id::text FROM applications WHERE id = $1", applicationID).Scan(&clubID)
	if errors.Is(err, sql.ErrNoRows) {
		return applicationRecord{}, errApplicationNotFound
	}
	if err != nil {
		return applicationRecord{}, err
	}
	var decided applicationRecord
	err = runReadCommitted(ctx, db, func(tx *sql.Tx) error {
		var clubStatus string
		err := tx.QueryRowContext(ctx, "SELECT status FROM clubs WHERE id = $1 FOR UPDATE", clubID).Scan(&clubStatus)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && clubStatus != "active") {
			return errApplicationNotFound
		}
		if err != nil {
			return err
		}
		if err := lockAdministrator(tx, actorID, clubID, true); err != nil {
			return err
		}
		var userID, actualClubID, status string
		if err := tx.QueryRowContext(ctx, `
			SELECT user_id::text, club_id::text, status
			FROM applications WHERE id = $1 FOR UPDATE`, applicationID,
		).Scan(&userID, &actualClubID, &status); errors.Is(err, sql.ErrNoRows) {
			return errApplicationNotFound
		} else if err != nil {
			return err
		}
		if actualClubID != clubID {
			return errApplicationNotFound
		}
		if status != "pending" {
			return errApplicationConflict
		}
		var administratorID string
		if err := tx.QueryRowContext(ctx, `
			UPDATE applications
			SET status = $1, administrator_id = $2, decided_at = now()
			WHERE id = $3 AND status = 'pending'
			RETURNING id::text, user_id::text, club_id::text, text, status, created_at,
			          administrator_id::text, decided_at`, decision, actorID, applicationID,
		).Scan(&decided.ID, &decided.UserID, &decided.ClubID, &decided.Text, &decided.Status,
			&decided.CreatedAt, &administratorID, &decided.DecidedAt); err != nil {
			return err
		}
		decided.AdministratorID = &administratorID
		if decision == "approved" {
			var membershipUserID string
			err := tx.QueryRowContext(ctx, `
				SELECT user_id::text FROM club_memberships
				WHERE user_id = $1 AND club_id = $2 FOR UPDATE`, userID, clubID,
			).Scan(&membershipUserID)
			if errors.Is(err, sql.ErrNoRows) {
				_, err = tx.ExecContext(ctx, `
					INSERT INTO club_memberships (user_id, club_id, created_at)
					VALUES ($1, $2, now()) ON CONFLICT (user_id, club_id) DO NOTHING`, userID, clubID)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return applicationRecord{}, err
	}
	return decided, nil
}

func changeMembership(ctx context.Context, db *sql.DB, actorID, clubID, userID string, add bool) error {
	return runReadCommitted(ctx, db, func(tx *sql.Tx) error {
		if err := lockActiveClub(tx, clubID); err != nil {
			return err
		}
		if err := lockAdministrator(tx, actorID, clubID, false); err != nil {
			return err
		}
		var targetExists bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)", userID).Scan(&targetExists); err != nil {
			return err
		}
		if !targetExists {
			return errApplicationNotFound
		}
		var membershipUserID string
		err := tx.QueryRowContext(ctx, `
			SELECT user_id::text FROM club_memberships
			WHERE user_id = $1 AND club_id = $2 FOR UPDATE`, userID, clubID).Scan(&membershipUserID)
		if add {
			if err == nil {
				return nil
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			_, err = tx.ExecContext(ctx, `
				INSERT INTO club_memberships (user_id, club_id, created_at)
				VALUES ($1, $2, now()) ON CONFLICT (user_id, club_id) DO NOTHING`, userID, clubID)
			return err
		}
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM club_memberships WHERE user_id = $1 AND club_id = $2", userID, clubID)
		return err
	})
}

func lockActiveClub(tx *sql.Tx, clubID string) error {
	var status string
	err := tx.QueryRow("SELECT status FROM clubs WHERE id = $1 FOR UPDATE", clubID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return errApplicationNotFound
	}
	if err != nil {
		return err
	}
	if status != "active" {
		return errApplicationConflict
	}
	return nil
}

func lockAdministrator(tx *sql.Tx, actorID, clubID string, hideUnauthorized bool) error {
	var role string
	err := tx.QueryRow(`
		SELECT users.global_role
		FROM club_administrators AS administrators
		JOIN users ON users.id = administrators.user_id
		WHERE administrators.user_id = $1 AND administrators.club_id = $2
		FOR UPDATE OF administrators`, actorID, clubID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && role != "User") {
		if hideUnauthorized {
			return errApplicationNotFound
		}
		return errApplicationForbidden
	}
	return err
}

func readGlobalRole(tx *sql.Tx, userID string) (string, error) {
	var role string
	err := tx.QueryRow("SELECT global_role FROM users WHERE id = $1", userID).Scan(&role)
	return role, err
}

func runReadCommitted(ctx context.Context, db *sql.DB, operation func(*sql.Tx) error) error {
	for attempt := 1; attempt <= maxTransactionAttempts; attempt++ {
		tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
		if err != nil {
			return err
		}
		err = operation(tx)
		if err != nil {
			rollbackErr := tx.Rollback()
			if isDeadlockError(err) && rollbackErr == nil {
				if attempt == maxTransactionAttempts {
					return errTransactionRetriesExhausted
				}
				if err := waitTransactionRetry(ctx); err != nil {
					return err
				}
				continue
			}
			return err
		}
		if err := tx.Commit(); err != nil {
			return transactionOutcomeUnknownError{cause: err}
		}
		return nil
	}
	return errTransactionRetriesExhausted
}

func waitTransactionRetry(ctx context.Context) error {
	var random [1]byte
	_, _ = rand.Read(random[:])
	delay := 10*time.Millisecond + time.Duration(random[0]%21)*time.Millisecond
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isDeadlockError(err error) bool {
	type sqlState interface{ SQLState() string }
	var state sqlState
	return errors.As(err, &state) && state.SQLState() == "40P01"
}

func scanApplication(scanner rowScanner) (applicationRecord, error) {
	var application applicationRecord
	var administratorID sql.NullString
	var decidedAt sql.NullTime
	if err := scanner.Scan(&application.ID, &application.UserID, &application.ClubID,
		&application.Text, &application.Status, &application.CreatedAt, &administratorID, &decidedAt); err != nil {
		return applicationRecord{}, err
	}
	if administratorID.Valid {
		application.AdministratorID = &administratorID.String
	}
	if decidedAt.Valid {
		application.DecidedAt = &decidedAt.Time
	}
	return application, nil
}

func requireEmptyBody(w http.ResponseWriter, r *http.Request) error {
	if r.Body == nil {
		return nil
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err != nil {
		return err
	}
	if len(body) != 0 {
		return ErrInvalidInput
	}
	return nil
}

func allowSafeOrigin(w http.ResponseWriter, r *http.Request, trustedOrigin string) bool {
	origins := r.Header.Values("Origin")
	if len(origins) > 1 || (len(origins) == 1 && origins[0] != trustedOrigin) {
		writeError(w, http.StatusForbidden, "origin is not allowed")
		return false
	}
	return true
}

func isUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, char := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if char != '-' {
				return false
			}
			continue
		}
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return true
}

func writeApplicationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "invalid request")
	case errors.Is(err, errApplicationNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, errApplicationForbidden):
		writeError(w, http.StatusForbidden, "operation is not allowed")
	case errors.Is(err, errApplicationConflict):
		writeError(w, http.StatusConflict, "request conflicts with current state")
	case errors.Is(err, errTransactionRetriesExhausted):
		writeError(w, http.StatusServiceUnavailable, "service unavailable")
	default:
		var outcomeUnknown transactionOutcomeUnknownError
		if errors.As(err, &outcomeUnknown) {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]string{"error": "transaction outcome unknown", "code": "transaction_outcome_unknown"})
			return
		}
		writeError(w, http.StatusInternalServerError, "request failed")
	}
}
