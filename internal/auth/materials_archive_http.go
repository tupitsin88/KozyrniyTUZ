package auth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"
)

type materialInput struct {
	Content string `json:"content"`
}

type materialRecord struct {
	ID        string    `json:"id"`
	ClubID    string    `json:"club_id"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (h *HTTPHandler) clubRoutes(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "query parameters are not supported")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/clubs/"), "/")
	switch {
	case len(parts) == 1 && isUUID(parts[0]):
		h.archiveClub(w, r, parts[0])
	case len(parts) == 2 && isUUID(parts[0]) && parts[1] == "materials":
		h.clubMaterials(w, r, parts[0])
	case len(parts) == 3 && isUUID(parts[0]) && parts[1] == "members" && isUUID(parts[2]):
		h.clubMemberships(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *HTTPHandler) clubMaterials(w http.ResponseWriter, r *http.Request, clubID string) {
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "query parameters are not supported")
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.listClubMaterials(w, r, clubID)
	case http.MethodPost:
		h.createClubMaterial(w, r, clubID)
	default:
		methodNotAllowed(w, "GET, POST")
	}
}

func (h *HTTPHandler) listClubMaterials(w http.ResponseWriter, r *http.Request, clubID string) {
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
	materials, err := readClubMaterials(r.Context(), h.service.db, principal.UserID, clubID)
	if err != nil {
		writeApplicationError(w, err)
		return
	}
	writeJSON(w, materials)
}

func (h *HTTPHandler) createClubMaterial(w http.ResponseWriter, r *http.Request, clubID string) {
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
	var input materialInput
	if !decodeJSON(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.Content) == "" {
		writeApplicationError(w, ErrInvalidInput)
		return
	}
	created, err := createMaterial(r.Context(), h.service.db, principal.UserID, clubID, input.Content)
	if err != nil {
		writeApplicationError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, created)
}

func (h *HTTPHandler) material(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "query parameters are not supported")
		return
	}
	materialID := strings.TrimPrefix(r.URL.Path, "/api/materials/")
	if !isUUID(materialID) {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.readMaterial(w, r, materialID)
	case http.MethodPut:
		h.updateMaterial(w, r, materialID)
	default:
		methodNotAllowed(w, "GET, PUT")
	}
}

func (h *HTTPHandler) readMaterial(w http.ResponseWriter, r *http.Request, materialID string) {
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
	material, err := readMaterial(r.Context(), h.service.db, principal.UserID, materialID)
	if err != nil {
		writeApplicationError(w, err)
		return
	}
	writeJSON(w, material)
}

func (h *HTTPHandler) updateMaterial(w http.ResponseWriter, r *http.Request, materialID string) {
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
	var input materialInput
	if !decodeJSON(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.Content) == "" {
		writeApplicationError(w, ErrInvalidInput)
		return
	}
	updated, err := updateMaterial(r.Context(), h.service.db, principal.UserID, materialID, input.Content)
	if err != nil {
		writeApplicationError(w, err)
		return
	}
	writeJSON(w, updated)
}

func (h *HTTPHandler) archiveClub(w http.ResponseWriter, r *http.Request, clubID string) {
	if r.Method != http.MethodDelete {
		methodNotAllowed(w, http.MethodDelete)
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
	if err := archiveClub(r.Context(), h.service.db, principal.UserID, clubID); err != nil {
		writeApplicationError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func readClubMaterials(ctx context.Context, db *sql.DB, actorID, clubID string) ([]materialRecord, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT materials.id::text, materials.club_id::text, materials.content,
		       materials.created_at, materials.updated_at
		FROM materials
		JOIN clubs ON clubs.id = materials.club_id
		WHERE materials.club_id = $1
		  AND clubs.status = 'active'
		  AND EXISTS (
		      SELECT 1 FROM club_memberships AS memberships
		      WHERE memberships.user_id = $2 AND memberships.club_id = materials.club_id
		  )
		ORDER BY materials.created_at DESC, materials.id`, clubID, actorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	materials := make([]materialRecord, 0)
	for rows.Next() {
		var material materialRecord
		if err := rows.Scan(&material.ID, &material.ClubID, &material.Content,
			&material.CreatedAt, &material.UpdatedAt); err != nil {
			return nil, err
		}
		materials = append(materials, material)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return materials, nil
}

func readMaterial(ctx context.Context, db *sql.DB, actorID, materialID string) (materialRecord, error) {
	var material materialRecord
	err := db.QueryRowContext(ctx, `
		SELECT materials.id::text, materials.club_id::text, materials.content,
		       materials.created_at, materials.updated_at
		FROM materials
		JOIN clubs ON clubs.id = materials.club_id
		WHERE materials.id = $1
		  AND clubs.status = 'active'
		  AND EXISTS (
		      SELECT 1 FROM club_memberships AS memberships
		      WHERE memberships.user_id = $2 AND memberships.club_id = materials.club_id
		  )`, materialID, actorID).Scan(&material.ID, &material.ClubID, &material.Content,
		&material.CreatedAt, &material.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return materialRecord{}, errApplicationNotFound
	}
	return material, err
}

func createMaterial(ctx context.Context, db *sql.DB, actorID, clubID, content string) (materialRecord, error) {
	var created materialRecord
	err := runReadCommitted(ctx, db, func(tx *sql.Tx) error {
		if err := lockActiveClub(tx, clubID); err != nil {
			return err
		}
		if err := lockAdministrator(tx, actorID, clubID, false); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `
			INSERT INTO materials (club_id, content, created_at, updated_at)
			VALUES ($1, $2, now(), now())
			RETURNING id::text, club_id::text, content, created_at, updated_at`,
			clubID, content).Scan(&created.ID, &created.ClubID, &created.Content,
			&created.CreatedAt, &created.UpdatedAt)
	})
	if err != nil {
		return materialRecord{}, err
	}
	return created, nil
}

func updateMaterial(ctx context.Context, db *sql.DB, actorID, materialID, content string) (materialRecord, error) {
	var clubID string
	err := db.QueryRowContext(ctx, "SELECT club_id::text FROM materials WHERE id = $1", materialID).Scan(&clubID)
	if errors.Is(err, sql.ErrNoRows) {
		return materialRecord{}, errApplicationNotFound
	}
	if err != nil {
		return materialRecord{}, err
	}
	var updated materialRecord
	err = runReadCommitted(ctx, db, func(tx *sql.Tx) error {
		if err := lockActiveClub(tx, clubID); err != nil {
			return err
		}
		if err := lockAdministrator(tx, actorID, clubID, true); err != nil {
			return err
		}
		var savedClubID string
		err := tx.QueryRowContext(ctx,
			"SELECT club_id::text FROM materials WHERE id = $1 FOR UPDATE", materialID).Scan(&savedClubID)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && savedClubID != clubID) {
			return errApplicationNotFound
		}
		if err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `
			UPDATE materials
			SET content = $1, updated_at = GREATEST(clock_timestamp(), updated_at, created_at)
			WHERE id = $2 AND club_id = $3
			RETURNING id::text, club_id::text, content, created_at, updated_at`,
			content, materialID, clubID).Scan(&updated.ID, &updated.ClubID, &updated.Content,
			&updated.CreatedAt, &updated.UpdatedAt)
	})
	if err != nil {
		return materialRecord{}, err
	}
	return updated, nil
}

func archiveClub(ctx context.Context, db *sql.DB, actorID, clubID string) error {
	return runReadCommitted(ctx, db, func(tx *sql.Tx) error {
		if err := lockActiveClub(tx, clubID); err != nil {
			return err
		}
		role, err := readGlobalRole(tx, actorID)
		if err != nil {
			return err
		}
		if role != "SuperUser" {
			return errApplicationForbidden
		}
		_, err = tx.ExecContext(ctx, `
			UPDATE clubs SET status = 'archived', archived_at = now()
			WHERE id = $1 AND status = 'active'`, clubID)
		return err
	})
}
