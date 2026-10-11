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
	"sync"
	"testing"
	"time"

	"github.com/tupitsin88/KozyrniyTUZ/internal/config"
	"github.com/tupitsin88/KozyrniyTUZ/internal/database"
)

func TestPostgresMaterialsAndArchiveLifecycle(t *testing.T) {
	baseURL := os.Getenv("AUTH_TEST_DATABASE_URL")
	if baseURL == "" {
		t.Skip("AUTH_TEST_DATABASE_URL is not set")
	}
	adminDB, err := sql.Open("pgx", baseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer adminDB.Close()
	schema := fmt.Sprintf("materials_archive_test_%d", time.Now().UnixNano())
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
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db, err := database.Open(ctx, parsedURL.String(), database.PoolConfig{
		MaxOpenConns: 12, MaxIdleConns: 6, ConnMaxLifetime: time.Minute, ConnMaxIdleTime: time.Minute,
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
	rootPassword := "root password with enough length"
	if err := service.Bootstrap(ctx, "materialsroot", rootPassword); err != nil {
		t.Fatal(err)
	}
	root, err := loginTestSession(ctx, service, "materialsroot", rootPassword)
	if err != nil {
		t.Fatal(err)
	}
	register := func(login string) applicationTestSession {
		t.Helper()
		userID, raw, csrf, err := service.Register(ctx, login, "correct horse battery staple", "")
		if err != nil {
			t.Fatal(err)
		}
		return applicationTestSession{
			userID: userID,
			cookie: base64.RawURLEncoding.EncodeToString(raw),
			csrf:   base64.RawURLEncoding.EncodeToString(csrf),
		}
	}
	adminA := register("matadmina")
	adminB := register("matadminb")
	member := register("matmember")
	outsider := register("matoutsider")
	lateApplicant := register("matapplicant")
	handler := NewHTTPHandler(service)
	createClub := func(session applicationTestSession, name string) string {
		t.Helper()
		body, err := json.Marshal(clubInput{Name: name, Description: "test club"})
		if err != nil {
			t.Fatal(err)
		}
		response := applicationAPIRequest(handler, service, &session, http.MethodPost, "/api/clubs", string(body), settings.TrustedOrigin, session.csrf)
		if response.Code != http.StatusCreated {
			t.Fatalf("create club %q status = %d; body=%s", name, response.Code, response.Body.String())
		}
		var club clubCreated
		if err := json.Unmarshal(response.Body.Bytes(), &club); err != nil {
			t.Fatal(err)
		}
		return club.ID
	}
	clubA := createClub(adminA, "Materials Club A")
	clubB := createClub(adminB, "Materials Club B")
	createMaterial := func(session applicationTestSession, clubID, content string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(materialInput{Content: content})
		if err != nil {
			t.Fatal(err)
		}
		return applicationAPIRequest(handler, service, &session, http.MethodPost,
			"/api/clubs/"+clubID+"/materials", string(body), settings.TrustedOrigin, session.csrf)
	}
	readMaterial := func(session applicationTestSession, materialID string) *httptest.ResponseRecorder {
		t.Helper()
		return applicationAPIRequest(handler, service, &session, http.MethodGet,
			"/api/materials/"+materialID, "", "", "")
	}
	updateMaterial := func(session applicationTestSession, materialID, body string) *httptest.ResponseRecorder {
		t.Helper()
		return applicationAPIRequest(handler, service, &session, http.MethodPut,
			"/api/materials/"+materialID, body, settings.TrustedOrigin, session.csrf)
	}
	archive := func(session applicationTestSession, clubID, origin, csrf, body string) *httptest.ResponseRecorder {
		t.Helper()
		return applicationAPIRequest(handler, service, &session, http.MethodDelete,
			"/api/clubs/"+clubID, body, origin, csrf)
	}
	if response := applicationAPIRequest(handler, service, &adminA, http.MethodPut,
		"/api/clubs/"+clubA+"/members/"+member.userID, "", settings.TrustedOrigin, adminA.csrf); response.Code != http.StatusNoContent {
		t.Fatalf("add club A member status = %d; body=%s", response.Code, response.Body.String())
	}
	memberList := applicationAPIRequest(handler, service, &adminA, http.MethodGet,
		"/api/clubs/"+clubA+"/members", "", "", "")
	if memberList.Code != http.StatusOK {
		t.Fatalf("authorized club member list status = %d; body=%s", memberList.Code, memberList.Body.String())
	}
	var clubMembers []clubMemberRecord
	if err := json.Unmarshal(memberList.Body.Bytes(), &clubMembers); err != nil {
		t.Fatal(err)
	}
	if len(clubMembers) != 2 {
		t.Fatalf("club member list count = %d, want 2: %#v", len(clubMembers), clubMembers)
	}
	for _, session := range []*applicationTestSession{&outsider, &adminB, &root} {
		if response := applicationAPIRequest(handler, service, session, http.MethodGet,
			"/api/clubs/"+clubA+"/members", "", "", ""); response.Code != http.StatusNotFound {
			t.Fatalf("unauthorized club member list status = %d, want %d", response.Code, http.StatusNotFound)
		}
	}
	if response := applicationAPIRequest(handler, service, &member, http.MethodPut,
		"/api/clubs/"+clubB+"/members/"+member.userID, "", settings.TrustedOrigin, member.csrf); response.Code != http.StatusForbidden {
		t.Fatalf("unauthorized club B membership change status = %d", response.Code)
	}

	content := "<script>plain text only</script>\nМатериал клуба A"
	created := createMaterial(adminA, clubA, content)
	if created.Code != http.StatusCreated {
		t.Fatalf("authorized material creation status = %d; body=%s", created.Code, created.Body.String())
	}
	var material materialRecord
	if err := json.Unmarshal(created.Body.Bytes(), &material); err != nil {
		t.Fatal(err)
	}
	if material.ID == "" || material.ClubID != clubA || material.Content != content || material.CreatedAt.IsZero() || material.UpdatedAt.Before(material.CreatedAt) {
		t.Fatalf("new material has unexpected fields: %#v", material)
	}
	if response := createMaterial(adminA, clubB, "wrong club"); response.Code != http.StatusForbidden {
		t.Fatalf("other-club material creation status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if response := createMaterial(outsider, clubA, "unauthorized"); response.Code != http.StatusForbidden {
		t.Fatalf("ordinary user's material creation status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if response := createMaterial(root, clubA, "SuperUser has no content access"); response.Code != http.StatusForbidden {
		t.Fatalf("SuperUser material creation status = %d, want %d", response.Code, http.StatusForbidden)
	}
	spoofedMaterial := fmt.Sprintf(`{"content":"spoof","club_id":%q,"id":%q}`, clubB, material.ID)
	if response := createMaterialBody(handler, service, adminA, clubA, spoofedMaterial, settings.TrustedOrigin, adminA.csrf); response.Code != http.StatusBadRequest {
		t.Fatalf("material protected field injection status = %d", response.Code)
	}
	if response := createMaterialBody(handler, service, adminA, clubA, `{"content":"bad"}`, "", adminA.csrf); response.Code != http.StatusForbidden {
		t.Fatalf("material create without Origin status = %d", response.Code)
	}
	if response := createMaterialBody(handler, service, adminA, clubA, `{"content":"bad"}`, settings.TrustedOrigin, "invalid"); response.Code != http.StatusForbidden {
		t.Fatalf("material create with invalid CSRF status = %d", response.Code)
	}
	if response := applicationAPIRequest(handler, service, nil, http.MethodGet,
		"/api/materials/"+material.ID, "", "", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous material read status = %d", response.Code)
	}
	if response := readMaterial(outsider, material.ID); response.Code != http.StatusNotFound {
		t.Fatalf("nonmember direct material read status = %d, want %d", response.Code, http.StatusNotFound)
	}
	if response := readMaterial(root, material.ID); response.Code != http.StatusNotFound {
		t.Fatalf("SuperUser direct material read status = %d, want %d", response.Code, http.StatusNotFound)
	}
	if response := readMaterial(member, material.ID); response.Code != http.StatusOK {
		t.Fatalf("authorized direct material read status = %d; body=%s", response.Code, response.Body.String())
	} else {
		var read materialRecord
		if err := json.Unmarshal(response.Body.Bytes(), &read); err != nil {
			t.Fatal(err)
		}
		if read.ID != material.ID || read.ClubID != clubA || read.Content != content {
			t.Fatalf("direct material response does not match saved object: %#v", read)
		}
	}
	if response := applicationAPIRequest(handler, service, &member, http.MethodGet,
		"/api/clubs/"+clubA+"/materials", "", "", ""); response.Code != http.StatusOK {
		t.Fatalf("authorized material list status = %d", response.Code)
	} else {
		var list []materialRecord
		if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		if len(list) != 1 || list[0].ID != material.ID {
			t.Fatalf("member received unexpected material collection: %#v", list)
		}
	}
	if response := applicationAPIRequest(handler, service, &outsider, http.MethodGet,
		"/api/clubs/"+clubA+"/materials", "", "", ""); response.Code != http.StatusOK {
		t.Fatalf("nonmember material list status = %d", response.Code)
	} else {
		var list []materialRecord
		if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		if len(list) != 0 {
			t.Fatalf("nonmember received materials: %#v", list)
		}
	}
	if response := applicationAPIRequest(handler, service, &adminA, http.MethodPost,
		"/api/clubs/"+clubA+"/members", `{"login":" matoutsider "}`, settings.TrustedOrigin, adminA.csrf); response.Code != http.StatusNoContent {
		t.Fatalf("authorized member addition by login status = %d; body=%s", response.Code, response.Body.String())
	}
	if response := applicationAPIRequest(handler, service, &adminA, http.MethodPost,
		"/api/clubs/"+clubA+"/members", `{"login":"matoutsider"}`, settings.TrustedOrigin, adminA.csrf); response.Code != http.StatusNoContent {
		t.Fatalf("idempotent member addition by login status = %d", response.Code)
	}
	if response := applicationAPIRequest(handler, service, &member, http.MethodPost,
		"/api/clubs/"+clubA+"/members", `{"login":"matapplicant"}`, settings.TrustedOrigin, member.csrf); response.Code != http.StatusForbidden {
		t.Fatalf("unauthorized addition by login status = %d", response.Code)
	}
	if response := applicationAPIRequest(handler, service, &adminA, http.MethodPost,
		"/api/clubs/"+clubA+"/members", `{"login":"unknownuser"}`, settings.TrustedOrigin, adminA.csrf); response.Code != http.StatusNotFound {
		t.Fatalf("unknown account addition status = %d", response.Code)
	}
	if response := readMaterial(outsider, material.ID); response.Code != http.StatusOK {
		t.Fatalf("new member did not receive access to club materials: status=%d", response.Code)
	}
	if response := applicationAPIRequest(handler, service, &member, http.MethodGet,
		"/api/clubs/"+clubA+"/materials", "", "http://attacker.example", ""); response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin material list status = %d", response.Code)
	}
	if response := applicationAPIRequest(handler, service, &outsider, http.MethodGet,
		"/api/clubs/"+clubB+"/materials", "", "", ""); response.Code != http.StatusOK {
		t.Fatalf("other club material list status = %d", response.Code)
	} else {
		var list []materialRecord
		if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		if len(list) != 0 {
			t.Fatalf("empty club returned materials: %#v", list)
		}
	}
	if response := updateMaterial(adminB, material.ID, `{"content":"wrong club update"}`); response.Code != http.StatusNotFound {
		t.Fatalf("other-club material update status = %d", response.Code)
	}
	if response := updateMaterial(member, material.ID, `{"content":"member update"}`); response.Code != http.StatusNotFound {
		t.Fatalf("member material update status = %d", response.Code)
	}
	if response := updateMaterial(root, material.ID, `{"content":"SuperUser update"}`); response.Code != http.StatusNotFound {
		t.Fatalf("SuperUser material update status = %d", response.Code)
	}
	if response := updateMaterial(adminA, material.ID,
		fmt.Sprintf(`{"content":"changed","club_id":%q}`, clubB)); response.Code != http.StatusBadRequest {
		t.Fatalf("material update with club reassignment status = %d", response.Code)
	}
	updated := updateMaterial(adminA, material.ID, `{"content":"updated plain text"}`)
	if updated.Code != http.StatusOK {
		t.Fatalf("authorized material update status = %d; body=%s", updated.Code, updated.Body.String())
	}
	var updatedMaterial materialRecord
	if err := json.Unmarshal(updated.Body.Bytes(), &updatedMaterial); err != nil {
		t.Fatal(err)
	}
	if updatedMaterial.ID != material.ID || updatedMaterial.ClubID != clubA || updatedMaterial.Content != "updated plain text" || !updatedMaterial.CreatedAt.Equal(material.CreatedAt) || updatedMaterial.UpdatedAt.Before(material.UpdatedAt) {
		t.Fatalf("material update changed protected fields or failed to update content: %#v", updatedMaterial)
	}
	if response := applicationAPIRequest(handler, service, &adminA, http.MethodPut,
		"/api/materials/"+material.ID, `{"content":"bad origin"}`, "", adminA.csrf); response.Code != http.StatusForbidden {
		t.Fatalf("material update without Origin status = %d", response.Code)
	}
	if response := applicationAPIRequest(handler, service, &adminA, http.MethodPut,
		"/api/materials/"+material.ID, `{"content":"bad csrf"}`, settings.TrustedOrigin, "invalid"); response.Code != http.StatusForbidden {
		t.Fatalf("material update with invalid CSRF status = %d", response.Code)
	}
	var persistedContent string
	if err := db.QueryRowContext(ctx, "SELECT content FROM materials WHERE id = $1", material.ID).Scan(&persistedContent); err != nil {
		t.Fatal(err)
	}
	if persistedContent != "updated plain text" {
		t.Fatalf("rejected updates changed saved content to %q", persistedContent)
	}
	applicationBody, err := json.Marshal(applicationInput{ClubID: clubA, Text: "application retained after archive"})
	if err != nil {
		t.Fatal(err)
	}
	archivedApplication := applicationAPIRequest(handler, service, &lateApplicant, http.MethodPost,
		"/api/applications", string(applicationBody), settings.TrustedOrigin, lateApplicant.csrf)
	if archivedApplication.Code != http.StatusCreated {
		t.Fatalf("archive fixture application status = %d; body=%s", archivedApplication.Code, archivedApplication.Body.String())
	}
	var savedApplication applicationRecord
	if err := json.Unmarshal(archivedApplication.Body.Bytes(), &savedApplication); err != nil {
		t.Fatal(err)
	}

	if response := archive(adminA, clubA, settings.TrustedOrigin, adminA.csrf, ""); response.Code != http.StatusForbidden {
		t.Fatalf("club administrator archive status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if response := archive(outsider, clubA, settings.TrustedOrigin, outsider.csrf, ""); response.Code != http.StatusForbidden {
		t.Fatalf("ordinary user archive status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if response := archive(adminA, clubA, "", adminA.csrf, ""); response.Code != http.StatusForbidden {
		t.Fatalf("archive without Origin status = %d", response.Code)
	}
	if response := archive(root, clubA, settings.TrustedOrigin, "invalid", ""); response.Code != http.StatusForbidden {
		t.Fatalf("archive with invalid CSRF status = %d", response.Code)
	}
	if response := archive(root, clubA, settings.TrustedOrigin, root.csrf, `{}`); response.Code != http.StatusBadRequest {
		t.Fatalf("archive with client body status = %d", response.Code)
	}
	if response := archive(root, clubA, settings.TrustedOrigin, root.csrf, ""); response.Code != http.StatusNoContent {
		t.Fatalf("SuperUser archive status = %d; body=%s", response.Code, response.Body.String())
	}
	var status string
	var archivedAt sql.NullTime
	if err := db.QueryRowContext(ctx, "SELECT status, archived_at FROM clubs WHERE id = $1", clubA).Scan(&status, &archivedAt); err != nil {
		t.Fatal(err)
	}
	if status != "archived" || !archivedAt.Valid {
		t.Fatalf("archived club state = %q, archived_at valid=%t", status, archivedAt.Valid)
	}
	var keptMaterials, keptMemberships, keptAdministrators int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM materials WHERE club_id = $1", clubA).Scan(&keptMaterials); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM club_memberships WHERE club_id = $1", clubA).Scan(&keptMemberships); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM club_administrators WHERE club_id = $1", clubA).Scan(&keptAdministrators); err != nil {
		t.Fatal(err)
	}
	if keptMaterials != 1 || keptMemberships != 3 || keptAdministrators != 1 {
		t.Fatalf("archive removed related rows: materials=%d memberships=%d administrators=%d", keptMaterials, keptMemberships, keptAdministrators)
	}
	if response := readMaterial(member, material.ID); response.Code != http.StatusNotFound {
		t.Fatalf("member read after archive status = %d", response.Code)
	}
	if response := applicationAPIRequest(handler, service, &member, http.MethodGet,
		"/api/clubs/"+clubA+"/materials", "", "", ""); response.Code != http.StatusOK {
		t.Fatalf("member list after archive status = %d", response.Code)
	} else {
		var list []materialRecord
		if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		if len(list) != 0 {
			t.Fatalf("archived club material list is not empty: %#v", list)
		}
	}
	if response := applicationAPIRequest(handler, service, &adminA, http.MethodGet,
		"/api/clubs/"+clubA+"/members", "", "", ""); response.Code != http.StatusNotFound {
		t.Fatalf("former administrator member list after archive status = %d", response.Code)
	}
	if response := createMaterial(adminA, clubA, "after archive"); response.Code != http.StatusConflict {
		t.Fatalf("material creation after archive status = %d", response.Code)
	}
	if response := updateMaterial(adminA, material.ID, `{"content":"after archive"}`); response.Code != http.StatusConflict {
		t.Fatalf("material update after archive status = %d", response.Code)
	}
	if response := archive(root, clubA, settings.TrustedOrigin, root.csrf, ""); response.Code != http.StatusConflict {
		t.Fatalf("repeat archive status = %d", response.Code)
	}
	clubsResponse := applicationAPIRequest(handler, service, &outsider, http.MethodGet, "/api/clubs", "", "", "")
	if clubsResponse.Code != http.StatusOK || strings.Contains(clubsResponse.Body.String(), clubA) {
		t.Fatalf("active club list includes archived club or failed: status=%d body=%s", clubsResponse.Code, clubsResponse.Body.String())
	}
	var applicationRows int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM applications WHERE club_id = $1", clubA).Scan(&applicationRows); err != nil {
		t.Fatal(err)
	}
	if applicationRows != 1 {
		t.Fatalf("archive did not preserve application: count=%d", applicationRows)
	}
	if response := applicationAPIRequest(handler, service, &lateApplicant, http.MethodGet,
		"/api/applications/"+savedApplication.ID, "", "", ""); response.Code != http.StatusOK {
		t.Fatalf("owner could not read preserved application after archive: status=%d body=%s", response.Code, response.Body.String())
	}
	adminApplications := applicationAPIRequest(handler, service, &adminA, http.MethodGet, "/api/applications", "", "", "")
	if adminApplications.Code != http.StatusOK {
		t.Fatalf("former administrator application list status = %d", adminApplications.Code)
	}
	var visibleApplications []applicationRecord
	if err := json.Unmarshal(adminApplications.Body.Bytes(), &visibleApplications); err != nil {
		t.Fatal(err)
	}
	for _, application := range visibleApplications {
		if application.ID == savedApplication.ID {
			t.Fatal("former administrator can still read applications of archived club")
		}
	}

	concurrentClub := createClub(adminA, "Archive Race Club")
	start := make(chan struct{})
	var wait sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, 2)
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		results <- createMaterial(adminA, concurrentClub, "created before archive or refused")
	}()
	go func() {
		defer wait.Done()
		<-start
		results <- archive(root, concurrentClub, settings.TrustedOrigin, root.csrf, "")
	}()
	close(start)
	wait.Wait()
	close(results)
	creationStatus, archiveStatus := 0, 0
	for response := range results {
		switch response.Code {
		case http.StatusCreated, http.StatusConflict:
			if response.Code == http.StatusCreated {
				creationStatus = response.Code
			} else {
				creationStatus = response.Code
			}
		case http.StatusNoContent:
			archiveStatus = response.Code
		default:
			t.Fatalf("concurrent operation returned unexpected status %d; body=%s", response.Code, response.Body.String())
		}
	}
	if archiveStatus != http.StatusNoContent || (creationStatus != http.StatusCreated && creationStatus != http.StatusConflict) {
		t.Fatalf("concurrent create/archive statuses = %d/%d", creationStatus, archiveStatus)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM materials WHERE club_id = $1", concurrentClub).Scan(&keptMaterials); err != nil {
		t.Fatal(err)
	}
	if creationStatus == http.StatusCreated && keptMaterials != 1 {
		t.Fatalf("committed material before archive was not preserved: count=%d", keptMaterials)
	}
	if creationStatus == http.StatusConflict && keptMaterials != 0 {
		t.Fatalf("material was created after archive won lock: count=%d", keptMaterials)
	}
}

func createMaterialBody(handler http.Handler, service *Service, session applicationTestSession, clubID, body, origin, csrf string) *httptest.ResponseRecorder {
	return applicationAPIRequest(handler, service, &session, http.MethodPost,
		"/api/clubs/"+clubID+"/materials", body, origin, csrf)
}
