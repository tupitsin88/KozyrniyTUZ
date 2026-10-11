package auth

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tupitsin88/KozyrniyTUZ/internal/config"
	"github.com/tupitsin88/KozyrniyTUZ/internal/database"
)

func TestPostgresClubAndProfileLifecycle(t *testing.T) {
	baseURL := os.Getenv("AUTH_TEST_DATABASE_URL")
	if baseURL == "" {
		t.Skip("AUTH_TEST_DATABASE_URL is not set")
	}
	adminDB, err := sql.Open("pgx", baseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer adminDB.Close()
	schema := fmt.Sprintf("clubs_test_%d", time.Now().UnixNano())
	if _, err := adminDB.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = adminDB.Exec("DROP SCHEMA " + schema + " CASCADE") })
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
	if err := service.Bootstrap(ctx, "rootuser", "bootstrap password with enough length"); err != nil {
		t.Fatal(err)
	}
	userID, userToken, userCSRF, err := service.Register(ctx, "clubcreator", "correct horse battery staple", "")
	if err != nil {
		t.Fatal(err)
	}
	rootID, rootToken, rootCSRF, err := service.Login(ctx, "rootuser", "bootstrap password with enough length", "")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTPHandler(service)
	userCookie := base64.RawURLEncoding.EncodeToString(userToken)
	userCSRFToken := base64.RawURLEncoding.EncodeToString(userCSRF)
	rootCookie := base64.RawURLEncoding.EncodeToString(rootToken)
	rootCSRFToken := base64.RawURLEncoding.EncodeToString(rootCSRF)
	postClub := func(cookie, csrf, origin, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/api/clubs", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		if csrf != "" {
			request.Header.Set("X-CSRF-Token", csrf)
		}
		if cookie != "" {
			request.AddCookie(&http.Cookie{Name: service.CookieName(), Value: cookie})
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	get := func(target, cookie string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, target, nil)
		if cookie != "" {
			request.AddCookie(&http.Cookie{Name: service.CookieName(), Value: cookie})
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	if response := get("/api/profile", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous profile status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if response := postClub(userCookie, userCSRFToken, "", `{"name":"Denied"}`); response.Code != http.StatusForbidden {
		t.Fatalf("missing origin create status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if response := postClub(userCookie, "invalid", settings.TrustedOrigin, `{"name":"Denied"}`); response.Code != http.StatusForbidden {
		t.Fatalf("invalid CSRF create status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if response := postClub(userCookie, userCSRFToken, settings.TrustedOrigin, `{"name":"Denied","creator_id":"`+rootID+`"}`); response.Code != http.StatusBadRequest {
		t.Fatalf("protected creator field status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	for _, field := range []string{"id", "user_id", "global_role", "status", "administrator_id", "membership_user_id"} {
		body := `{"name":"Denied","` + field + `":"` + rootID + `"}`
		if response := postClub(userCookie, userCSRFToken, settings.TrustedOrigin, body); response.Code != http.StatusBadRequest {
			t.Fatalf("protected %s field status = %d, want %d", field, response.Code, http.StatusBadRequest)
		}
	}
	if response := postClub(userCookie, userCSRFToken, settings.TrustedOrigin, `{"name":"   "}`); response.Code != http.StatusBadRequest {
		t.Fatalf("blank club name status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if response := postClub(rootCookie, rootCSRFToken, settings.TrustedOrigin, `{"name":"Denied"}`); response.Code != http.StatusForbidden {
		t.Fatalf("SuperUser create status = %d, want %d", response.Code, http.StatusForbidden)
	}
	profileOriginRequest := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	profileOriginRequest.AddCookie(&http.Cookie{Name: service.CookieName(), Value: userCookie})
	profileOriginRequest.Header.Set("Origin", "http://attacker.example")
	profileOriginResponse := httptest.NewRecorder()
	handler.ServeHTTP(profileOriginResponse, profileOriginRequest)
	if profileOriginResponse.Code != http.StatusForbidden {
		t.Fatalf("cross-origin profile status = %d, want %d", profileOriginResponse.Code, http.StatusForbidden)
	}

	first := postClub(userCookie, userCSRFToken, settings.TrustedOrigin, `{"name":"First","description":"Owned by creator"}`)
	if first.Code != http.StatusCreated {
		t.Fatalf("first create status = %d, want %d; body=%s", first.Code, http.StatusCreated, first.Body.String())
	}
	var firstClub clubCreated
	if err := json.Unmarshal(first.Body.Bytes(), &firstClub); err != nil {
		t.Fatal(err)
	}
	var creatorID string
	var status string
	if err := db.QueryRowContext(ctx, "SELECT creator_id::text, status FROM clubs WHERE id = $1", firstClub.ID).Scan(&creatorID, &status); err != nil {
		t.Fatal(err)
	}
	if creatorID != userID || status != "active" {
		t.Fatalf("stored club creator/status = %q/%q, want %q/active", creatorID, status, userID)
	}
	var administratorCount, membershipCount int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM club_administrators WHERE user_id = $1 AND club_id = $2", userID, firstClub.ID).Scan(&administratorCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM club_memberships WHERE user_id = $1 AND club_id = $2", userID, firstClub.ID).Scan(&membershipCount); err != nil {
		t.Fatal(err)
	}
	if administratorCount != 1 || membershipCount != 1 {
		t.Fatalf("creator relationships = administrator:%d membership:%d, want one each", administratorCount, membershipCount)
	}

	second := postClub(userCookie, userCSRFToken, settings.TrustedOrigin, `{"name":"Second","description":"<script>alert(1)</script>"}`)
	if second.Code != http.StatusCreated {
		t.Fatalf("Administrator creating another club status = %d, want %d; body=%s", second.Code, http.StatusCreated, second.Body.String())
	}
	var secondClub clubCreated
	if err := json.Unmarshal(second.Body.Bytes(), &secondClub); err != nil {
		t.Fatal(err)
	}
	if secondClub.Description != "<script>alert(1)</script>" {
		t.Fatalf("club description was changed: %q", secondClub.Description)
	}

	clubsResponse := get("/api/clubs", "")
	if clubsResponse.Code != http.StatusOK {
		t.Fatalf("public club list status = %d, want %d", clubsResponse.Code, http.StatusOK)
	}
	var clubs []map[string]any
	if err := json.Unmarshal(clubsResponse.Body.Bytes(), &clubs); err != nil {
		t.Fatal(err)
	}
	if len(clubs) != 2 {
		t.Fatalf("active club count = %d, want 2", len(clubs))
	}
	for _, club := range clubs {
		if len(club) != 3 {
			t.Fatalf("public club response fields = %#v, want only id, name and description", club)
		}
	}

	profileHTTPResponse := get("/api/profile?user_id="+rootID, userCookie)
	if profileHTTPResponse.Code != http.StatusOK {
		t.Fatalf("profile status = %d, want %d; body=%s", profileHTTPResponse.Code, http.StatusOK, profileHTTPResponse.Body.String())
	}
	var profile profileResponse
	if err := json.Unmarshal(profileHTTPResponse.Body.Bytes(), &profile); err != nil {
		t.Fatal(err)
	}
	if profile.ID != userID || profile.Login != "clubcreator" || profile.GlobalRole != "User" || len(profile.Clubs) != 2 || len(profile.AdministratorClubIDs) != 2 {
		t.Fatalf("profile = %#v, want current user and both active memberships", profile)
	}

	if _, err := db.ExecContext(ctx, "UPDATE clubs SET status = 'archived', archived_at = now() WHERE id = $1", firstClub.ID); err != nil {
		t.Fatal(err)
	}
	clubsResponse = get("/api/clubs", "")
	if err := json.Unmarshal(clubsResponse.Body.Bytes(), &clubs); err != nil {
		t.Fatal(err)
	}
	if len(clubs) != 1 {
		t.Fatalf("active club count after archive = %d, want 1", len(clubs))
	}
	profileHTTPResponse = get("/api/profile", userCookie)
	if err := json.Unmarshal(profileHTTPResponse.Body.Bytes(), &profile); err != nil {
		t.Fatal(err)
	}
	if len(profile.Clubs) != 1 || profile.Clubs[0].ID != secondClub.ID || len(profile.AdministratorClubIDs) != 1 || profile.AdministratorClubIDs[0] != secondClub.ID {
		t.Fatalf("profile includes archived membership: %#v", profile.Clubs)
	}

	var clubsBefore int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM clubs").Scan(&clubsBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		CREATE FUNCTION reject_membership_insert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'membership insertion rejected';
		END
		$$;
		CREATE TRIGGER reject_membership_insert BEFORE INSERT ON club_memberships
		FOR EACH ROW EXECUTE FUNCTION reject_membership_insert()`); err != nil {
		t.Fatal(err)
	}
	if response := postClub(userCookie, userCSRFToken, settings.TrustedOrigin, `{"name":"Must roll back"}`); response.Code != http.StatusInternalServerError {
		t.Fatalf("forced membership failure status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
	var clubsAfter, partialAdministratorCount int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM clubs").Scan(&clubsAfter); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM club_administrators WHERE user_id = $1", userID).Scan(&partialAdministratorCount); err != nil {
		t.Fatal(err)
	}
	if clubsAfter != clubsBefore || partialAdministratorCount != 2 {
		t.Fatalf("failed transaction left partial state: clubs %d -> %d, administrator rows %d", clubsBefore, clubsAfter, partialAdministratorCount)
	}
}
