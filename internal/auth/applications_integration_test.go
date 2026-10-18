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

type applicationTestSession struct {
	userID string
	cookie string
	csrf   string
}

func TestPostgresApplicationAndMembershipLifecycle(t *testing.T) {
	baseURL := os.Getenv("AUTH_TEST_DATABASE_URL")
	if baseURL == "" {
		t.Skip("AUTH_TEST_DATABASE_URL is not set")
	}
	adminDB, err := sql.Open("pgx", baseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer adminDB.Close()
	schema := fmt.Sprintf("applications_test_%d", time.Now().UnixNano())
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
	if err := service.Bootstrap(ctx, "applicationroot", rootPassword); err != nil {
		t.Fatal(err)
	}
	var rootID string
	if err := db.QueryRowContext(ctx, "SELECT id::text FROM users WHERE login = 'applicationroot'").Scan(&rootID); err != nil {
		t.Fatal(err)
	}
	rootToken, err := loginTestSession(ctx, service, "applicationroot", rootPassword)
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
	adminA := register("appadmina")
	adminB := register("appadminb")
	applicantA := register("applicantone")
	applicantB := register("applicanttwo")
	applicantC := register("applicantthree")
	concurrentApplicant := register("applicantconcurrent")
	rollbackApplicant := register("applicantrollback")
	deadlockApplicant := register("applicantdeadlock")
	exhaustedApplicant := register("applicantexhausted")
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
	clubA := createClub(adminA, "Application Club A")
	clubB := createClub(adminB, "Application Club B")

	submit := func(session applicationTestSession, clubID, text string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(applicationInput{ClubID: clubID, Text: text})
		if err != nil {
			t.Fatal(err)
		}
		return applicationAPIRequest(handler, service, &session, http.MethodPost, "/api/applications", string(body), settings.TrustedOrigin, session.csrf)
	}
	if response := submit(adminA, clubA, "already a member"); response.Code != http.StatusConflict {
		t.Fatalf("application submission by existing member status = %d, want %d", response.Code, http.StatusConflict)
	}
	requestDecision := func(session applicationTestSession, applicationID, decision string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(applicationDecisionInput{Status: decision})
		if err != nil {
			t.Fatal(err)
		}
		return applicationAPIRequest(handler, service, &session, http.MethodPost,
			"/api/applications/"+applicationID+"/decision", string(body), settings.TrustedOrigin, session.csrf)
	}
	changeMember := func(session applicationTestSession, method, clubID, userID, body string) *httptest.ResponseRecorder {
		t.Helper()
		return applicationAPIRequest(handler, service, &session, method,
			"/api/clubs/"+clubID+"/members/"+userID, body, settings.TrustedOrigin, session.csrf)
	}

	first := submit(applicantA, clubA, "<script>alert(1)</script>")
	if first.Code != http.StatusCreated {
		t.Fatalf("application submission status = %d, want %d; body=%s", first.Code, http.StatusCreated, first.Body.String())
	}
	var firstApplication applicationRecord
	if err := json.Unmarshal(first.Body.Bytes(), &firstApplication); err != nil {
		t.Fatal(err)
	}
	if firstApplication.UserID != applicantA.userID || firstApplication.ClubID != clubA || firstApplication.Status != "pending" || firstApplication.Text != "<script>alert(1)</script>" || firstApplication.AdministratorID != nil || firstApplication.DecidedAt != nil {
		t.Fatalf("new application has unexpected protected fields: %#v", firstApplication)
	}
	if response := submit(applicantA, clubA, "duplicate"); response.Code != http.StatusConflict {
		t.Fatalf("duplicate pending application status = %d, want %d", response.Code, http.StatusConflict)
	}
	if response := submit(applicantA, clubB, "pending in a different club"); response.Code != http.StatusCreated {
		t.Fatalf("cross-club application status = %d, want %d; body=%s", response.Code, http.StatusCreated, response.Body.String())
	}
	if response := applicationAPIRequest(handler, service, &applicantA, http.MethodGet,
		"/api/applications?user_id="+adminA.userID, "", "", ""); response.Code != http.StatusBadRequest {
		t.Fatalf("foreign user application filter status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	spoofBody := fmt.Sprintf(`{"club_id":%q,"text":"spoof","user_id":%q,"status":"approved"}`, clubA, adminA.userID)
	if response := applicationAPIRequest(handler, service, &applicantA, http.MethodPost, "/api/applications", spoofBody, settings.TrustedOrigin, applicantA.csrf); response.Code != http.StatusBadRequest {
		t.Fatalf("protected application fields status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if response := submit(rootToken, clubA, "not allowed"); response.Code != http.StatusForbidden {
		t.Fatalf("SuperUser application submission status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if response := applicationAPIRequest(handler, service, &applicantA, http.MethodPost, "/api/applications",
		fmt.Sprintf(`{"club_id":%q,"text":"missing origin"}`, clubA), "", applicantA.csrf); response.Code != http.StatusForbidden {
		t.Fatalf("submission without exact origin status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if response := applicationAPIRequest(handler, service, &applicantA, http.MethodPost, "/api/applications",
		fmt.Sprintf(`{"club_id":%q,"text":"bad csrf"}`, clubA), settings.TrustedOrigin, "invalid"); response.Code != http.StatusForbidden {
		t.Fatalf("submission with invalid CSRF status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if response := applicationAPIRequest(handler, service, nil, http.MethodPost, "/api/applications", `{"club_id":"`+clubA+`","text":"anonymous"}`, settings.TrustedOrigin, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous application submission status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if response := applicationAPIRequest(handler, service, nil, http.MethodGet, "/api/applications", "", "", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous application list status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if response := applicationAPIRequest(handler, service, &applicantA, http.MethodGet, "/api/applications/"+firstApplication.ID, "", "http://attacker.example", ""); response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin application read status = %d, want %d", response.Code, http.StatusForbidden)
	}

	applicantList := applicationAPIRequest(handler, service, &applicantA, http.MethodGet, "/api/applications", "", "", "")
	if applicantList.Code != http.StatusOK {
		t.Fatalf("owner application list status = %d", applicantList.Code)
	}
	var ownApplications []applicationRecord
	if err := json.Unmarshal(applicantList.Body.Bytes(), &ownApplications); err != nil {
		t.Fatal(err)
	}
	if len(ownApplications) != 2 {
		t.Fatalf("owner application count = %d, want 2", len(ownApplications))
	}
	for _, application := range ownApplications {
		if application.UserID != applicantA.userID {
			t.Fatalf("owner collection returned another user's application: %#v", application)
		}
	}
	adminList := applicationAPIRequest(handler, service, &adminA, http.MethodGet, "/api/applications", "", "", "")
	var adminApplications []applicationRecord
	if err := json.Unmarshal(adminList.Body.Bytes(), &adminApplications); err != nil {
		t.Fatal(err)
	}
	if len(adminApplications) != 1 || adminApplications[0].ID != firstApplication.ID {
		t.Fatalf("club A administrator application list = %#v, want only club A application", adminApplications)
	}
	adminCrossClubApplicationResponse := submit(adminA, clubB, "administrator retains User actions")
	if adminCrossClubApplicationResponse.Code != http.StatusCreated {
		t.Fatalf("Administrator applying to another club status = %d, want %d", adminCrossClubApplicationResponse.Code, http.StatusCreated)
	}
	var adminCrossClubApplication applicationRecord
	if err := json.Unmarshal(adminCrossClubApplicationResponse.Body.Bytes(), &adminCrossClubApplication); err != nil {
		t.Fatal(err)
	}
	for _, session := range []*applicationTestSession{&applicantB, &adminB, &rootToken} {
		if response := applicationAPIRequest(handler, service, session, http.MethodGet, "/api/applications/"+firstApplication.ID, "", "", ""); response.Code != http.StatusNotFound {
			t.Fatalf("unauthorized application read status = %d, want %d", response.Code, http.StatusNotFound)
		}
	}

	secondClubApplication := submit(applicantB, clubB, "club B request")
	if secondClubApplication.Code != http.StatusCreated {
		t.Fatalf("club B application status = %d", secondClubApplication.Code)
	}
	var clubBApplication applicationRecord
	if err := json.Unmarshal(secondClubApplication.Body.Bytes(), &clubBApplication); err != nil {
		t.Fatal(err)
	}
	adminList = applicationAPIRequest(handler, service, &adminA, http.MethodGet, "/api/applications", "", "", "")
	if err := json.Unmarshal(adminList.Body.Bytes(), &adminApplications); err != nil {
		t.Fatal(err)
	}
	assertCursorPagination(t, func(target string) *httptest.ResponseRecorder {
		return applicationAPIRequest(handler, service, &adminA, http.MethodGet, target, "", "", "")
	}, "/api/applications", func(application applicationRecord) string { return application.ID })
	for _, application := range adminApplications {
		if application.ID == clubBApplication.ID {
			t.Fatal("club A administrator received club B application")
		}
	}
	t.Run("T-05 to SR-04 to D-02 rejects unauthorized decisions without disclosure or state change", func(t *testing.T) {
		for _, testCase := range []struct {
			name    string
			session applicationTestSession
		}{
			{name: "applicant", session: applicantA},
			{name: "administrator of another club", session: adminB},
			{name: "SuperUser", session: rootToken},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				response := requestDecision(testCase.session, firstApplication.ID, "approved")
				if response.Code != http.StatusNotFound {
					t.Fatalf("decision status = %d, want %d", response.Code, http.StatusNotFound)
				}
				if strings.Contains(response.Body.String(), firstApplication.Text) {
					t.Fatalf("denied decision disclosed application text: %s", response.Body.String())
				}
			})
		}

		var status string
		var administratorID sql.NullString
		var decidedAt sql.NullTime
		if err := db.QueryRowContext(ctx, `
			SELECT status, administrator_id::text, decided_at
			FROM applications
			WHERE id = $1`, firstApplication.ID,
		).Scan(&status, &administratorID, &decidedAt); err != nil {
			t.Fatal(err)
		}
		if status != "pending" || administratorID.Valid || decidedAt.Valid {
			t.Fatalf("denied decisions changed application: status=%q administrator=%#v decided_at=%#v", status, administratorID, decidedAt)
		}
		assertMembershipCount(t, ctx, db, applicantA.userID, clubA, 0)
	})
	if response := applicationAPIRequest(handler, service, &adminA, http.MethodPost,
		"/api/applications/"+firstApplication.ID+"/decision", `{"status":"approved","administrator_id":"`+adminB.userID+`"}`, settings.TrustedOrigin, adminA.csrf); response.Code != http.StatusBadRequest {
		t.Fatalf("protected decision field status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if response := applicationAPIRequest(handler, service, &adminA, http.MethodPost,
		"/api/applications/"+firstApplication.ID+"/decision", `{"status":"approved"}`, settings.TrustedOrigin, "invalid"); response.Code != http.StatusForbidden {
		t.Fatalf("decision with invalid CSRF status = %d, want %d", response.Code, http.StatusForbidden)
	}
	t.Run("SR-04 to D-02 allows the current club administrator to approve", func(t *testing.T) {
		approved := requestDecision(adminA, firstApplication.ID, "approved")
		if approved.Code != http.StatusOK {
			t.Fatalf("authorized approval status = %d, want %d; body=%s", approved.Code, http.StatusOK, approved.Body.String())
		}
		var approvedApplication applicationRecord
		if err := json.Unmarshal(approved.Body.Bytes(), &approvedApplication); err != nil {
			t.Fatal(err)
		}
		if approvedApplication.Status != "approved" || approvedApplication.AdministratorID == nil || *approvedApplication.AdministratorID != adminA.userID || approvedApplication.DecidedAt == nil {
			t.Fatalf("approval response did not record current administrator and decision time: %#v", approvedApplication)
		}
		assertMembershipCount(t, ctx, db, applicantA.userID, clubA, 1)
	})
	t.Run("D-03 preserves the first completed decision", func(t *testing.T) {
		if response := requestDecision(adminA, firstApplication.ID, "rejected"); response.Code != http.StatusConflict {
			t.Fatalf("repeat decision status = %d, want %d", response.Code, http.StatusConflict)
		}
		assertMembershipCount(t, ctx, db, applicantA.userID, clubA, 1)
	})

	rejectedApplicationResponse := submit(applicantB, clubA, "will be rejected")
	if rejectedApplicationResponse.Code != http.StatusCreated {
		t.Fatalf("second club application status = %d", rejectedApplicationResponse.Code)
	}
	var rejectedApplication applicationRecord
	if err := json.Unmarshal(rejectedApplicationResponse.Body.Bytes(), &rejectedApplication); err != nil {
		t.Fatal(err)
	}
	rejected := requestDecision(adminA, rejectedApplication.ID, "rejected")
	if rejected.Code != http.StatusOK {
		t.Fatalf("authorized rejection status = %d, want %d; body=%s", rejected.Code, http.StatusOK, rejected.Body.String())
	}
	assertMembershipCount(t, ctx, db, applicantB.userID, clubA, 0)

	manualPendingResponse := submit(applicantC, clubA, "membership added before decision")
	if manualPendingResponse.Code != http.StatusCreated {
		t.Fatalf("manual membership application status = %d", manualPendingResponse.Code)
	}
	var manualPending applicationRecord
	if err := json.Unmarshal(manualPendingResponse.Body.Bytes(), &manualPending); err != nil {
		t.Fatal(err)
	}
	if response := changeMember(adminA, http.MethodPut, clubA, applicantC.userID, ""); response.Code != http.StatusNoContent {
		t.Fatalf("authorized member add status = %d, want %d", response.Code, http.StatusNoContent)
	}
	var membershipCreatedAt time.Time
	if err := db.QueryRowContext(ctx, "SELECT created_at FROM club_memberships WHERE user_id = $1 AND club_id = $2", applicantC.userID, clubA).Scan(&membershipCreatedAt); err != nil {
		t.Fatal(err)
	}
	var pendingStatus string
	if err := db.QueryRowContext(ctx, "SELECT status FROM applications WHERE id = $1", manualPending.ID).Scan(&pendingStatus); err != nil {
		t.Fatal(err)
	}
	if pendingStatus != "pending" {
		t.Fatalf("manual member add changed pending application to %q", pendingStatus)
	}
	if response := requestDecision(adminA, manualPending.ID, "approved"); response.Code != http.StatusOK {
		t.Fatalf("approval with pre-existing membership status = %d; body=%s", response.Code, response.Body.String())
	}
	var membershipRows int
	var membershipCreatedAtAfter time.Time
	if err := db.QueryRowContext(ctx, "SELECT count(*), min(created_at) FROM club_memberships WHERE user_id = $1 AND club_id = $2", applicantC.userID, clubA).Scan(&membershipRows, &membershipCreatedAtAfter); err != nil {
		t.Fatal(err)
	}
	if membershipRows != 1 || !membershipCreatedAtAfter.Equal(membershipCreatedAt) {
		t.Fatalf("approval replaced or duplicated existing membership: rows=%d created_at=%v want %v", membershipRows, membershipCreatedAtAfter, membershipCreatedAt)
	}
	if response := changeMember(adminA, http.MethodPut, clubA, applicantC.userID, ""); response.Code != http.StatusNoContent {
		t.Fatalf("idempotent member add status = %d", response.Code)
	}
	if response := changeMember(adminB, http.MethodPut, clubA, applicantB.userID, ""); response.Code != http.StatusForbidden {
		t.Fatalf("other-club administrator member add status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if response := changeMember(applicantA, http.MethodPut, clubA, applicantB.userID, ""); response.Code != http.StatusForbidden {
		t.Fatalf("ordinary user member add status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if response := changeMember(rootToken, http.MethodPut, clubA, applicantB.userID, ""); response.Code != http.StatusForbidden {
		t.Fatalf("SuperUser member add status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if response := changeMember(adminA, http.MethodPut, clubA, applicantB.userID, `{"user_id":"`+rootID+`"}`); response.Code != http.StatusBadRequest {
		t.Fatalf("membership request body status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if response := changeMember(adminA, http.MethodPut, clubA, applicantB.userID, ""); response.Code != http.StatusNoContent {
		t.Fatalf("authorized member add status = %d", response.Code)
	}
	if response := changeMember(applicantA, http.MethodDelete, clubA, applicantB.userID, ""); response.Code != http.StatusForbidden {
		t.Fatalf("ordinary user member removal status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if response := changeMember(adminB, http.MethodDelete, clubA, applicantB.userID, ""); response.Code != http.StatusForbidden {
		t.Fatalf("other-club administrator member removal status = %d, want %d", response.Code, http.StatusForbidden)
	}
	assertMembershipCount(t, ctx, db, applicantB.userID, clubA, 1)
	if response := changeMember(adminB, http.MethodPut, clubB, applicantB.userID, ""); response.Code != http.StatusNoContent {
		t.Fatalf("same user membership in second club status = %d", response.Code)
	}
	if response := changeMember(adminA, http.MethodDelete, clubA, applicantB.userID, ""); response.Code != http.StatusNoContent {
		t.Fatalf("authorized member removal status = %d", response.Code)
	}
	assertMembershipCount(t, ctx, db, applicantB.userID, clubA, 0)
	assertMembershipCount(t, ctx, db, applicantB.userID, clubB, 1)
	if response := changeMember(adminA, http.MethodDelete, clubA, applicantB.userID, ""); response.Code != http.StatusNoContent {
		t.Fatalf("idempotent member removal status = %d", response.Code)
	}
	if response := changeMember(adminA, http.MethodPut, clubA, "not-a-uuid", ""); response.Code != http.StatusNotFound {
		t.Fatalf("malformed membership target status = %d, want %d", response.Code, http.StatusNotFound)
	}

	concurrentCreate := make(chan *httptest.ResponseRecorder, 2)
	startCreate := make(chan struct{})
	var createWait sync.WaitGroup
	for index := 0; index < 2; index++ {
		createWait.Add(1)
		go func() {
			defer createWait.Done()
			<-startCreate
			concurrentCreate <- submit(concurrentApplicant, clubA, "concurrent request")
		}()
	}
	close(startCreate)
	createWait.Wait()
	close(concurrentCreate)
	createStatuses := map[int]int{}
	var concurrentApplication applicationRecord
	for response := range concurrentCreate {
		createStatuses[response.Code]++
		if response.Code == http.StatusCreated {
			if err := json.Unmarshal(response.Body.Bytes(), &concurrentApplication); err != nil {
				t.Fatal(err)
			}
		}
	}
	if createStatuses[http.StatusCreated] != 1 || createStatuses[http.StatusConflict] != 1 {
		t.Fatalf("concurrent submission statuses = %#v, want one 201 and one 409", createStatuses)
	}
	var concurrentPendingCount int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM applications WHERE user_id = $1 AND club_id = $2 AND status = 'pending'", concurrentApplicant.userID, clubA).Scan(&concurrentPendingCount); err != nil {
		t.Fatal(err)
	}
	if concurrentPendingCount != 1 {
		t.Fatalf("concurrent pending application count = %d, want 1", concurrentPendingCount)
	}

	t.Run("D-03 serializes concurrent opposite decisions", func(t *testing.T) {
		concurrentDecisions := make(chan *httptest.ResponseRecorder, 2)
		startDecision := make(chan struct{})
		var decisionWait sync.WaitGroup
		for _, decision := range []string{"approved", "rejected"} {
			decisionWait.Add(1)
			go func(decision string) {
				defer decisionWait.Done()
				<-startDecision
				concurrentDecisions <- requestDecision(adminA, concurrentApplication.ID, decision)
			}(decision)
		}
		close(startDecision)
		decisionWait.Wait()
		close(concurrentDecisions)
		decisionStatuses := map[int]int{}
		for response := range concurrentDecisions {
			decisionStatuses[response.Code]++
		}
		if decisionStatuses[http.StatusOK] != 1 || decisionStatuses[http.StatusConflict] != 1 {
			t.Fatalf("concurrent decision statuses = %#v, want one 200 and one 409", decisionStatuses)
		}
		var finalStatus string
		if err := db.QueryRowContext(ctx, "SELECT status FROM applications WHERE id = $1", concurrentApplication.ID).Scan(&finalStatus); err != nil {
			t.Fatal(err)
		}
		if finalStatus == "approved" {
			assertMembershipCount(t, ctx, db, concurrentApplicant.userID, clubA, 1)
		} else if finalStatus == "rejected" {
			assertMembershipCount(t, ctx, db, concurrentApplicant.userID, clubA, 0)
		} else {
			t.Fatalf("concurrent decision left invalid status %q", finalStatus)
		}
	})

	var rollbackApplication applicationRecord
	t.Run("D-03 rolls back the decision when membership creation fails", func(t *testing.T) {
		rollbackResponse := submit(rollbackApplicant, clubA, "rollback check")
		if rollbackResponse.Code != http.StatusCreated {
			t.Fatalf("rollback scenario submission status = %d", rollbackResponse.Code)
		}
		if err := json.Unmarshal(rollbackResponse.Body.Bytes(), &rollbackApplication); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `
			CREATE FUNCTION reject_test_membership_insert() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				RAISE EXCEPTION 'membership insertion rejected';
			END
			$$;
			CREATE TRIGGER reject_test_membership_insert BEFORE INSERT ON club_memberships
			FOR EACH ROW EXECUTE FUNCTION reject_test_membership_insert()`); err != nil {
			t.Fatal(err)
		}
		if response := requestDecision(adminA, rollbackApplication.ID, "approved"); response.Code != http.StatusInternalServerError {
			t.Fatalf("forced membership failure status = %d, want %d", response.Code, http.StatusInternalServerError)
		}
		var rollbackStatus string
		if err := db.QueryRowContext(ctx, "SELECT status FROM applications WHERE id = $1", rollbackApplication.ID).Scan(&rollbackStatus); err != nil {
			t.Fatal(err)
		}
		if rollbackStatus != "pending" {
			t.Fatalf("failed approval left status %q, want pending", rollbackStatus)
		}
		assertMembershipCount(t, ctx, db, rollbackApplicant.userID, clubA, 0)
		if _, err := db.ExecContext(ctx, "DROP TRIGGER reject_test_membership_insert ON club_memberships; DROP FUNCTION reject_test_membership_insert()"); err != nil {
			t.Fatal(err)
		}
	})

	if _, err := db.ExecContext(ctx, `
		CREATE SEQUENCE application_deadlock_test_sequence;
		CREATE FUNCTION raise_deadlock_once() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF nextval('application_deadlock_test_sequence') = 1 THEN
				RAISE EXCEPTION 'simulated deadlock' USING ERRCODE = '40P01';
			END IF;
			RETURN NEW;
		END
		$$;
		CREATE TRIGGER raise_deadlock_once BEFORE INSERT ON applications
		FOR EACH ROW EXECUTE FUNCTION raise_deadlock_once()`); err != nil {
		t.Fatal(err)
	}
	deadlockRetry := submit(deadlockApplicant, clubA, "deadlock retry")
	if deadlockRetry.Code != http.StatusCreated {
		t.Fatalf("confirmed deadlock retry status = %d, want %d; body=%s", deadlockRetry.Code, http.StatusCreated, deadlockRetry.Body.String())
	}
	var deadlockApplication applicationRecord
	if err := json.Unmarshal(deadlockRetry.Body.Bytes(), &deadlockApplication); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		CREATE OR REPLACE FUNCTION raise_deadlock_once() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'simulated repeated deadlock' USING ERRCODE = '40P01';
		END
		$$`); err != nil {
		t.Fatal(err)
	}
	if response := submit(exhaustedApplicant, clubA, "deadlock retry exhaustion"); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("repeated deadlock status = %d, want %d; body=%s", response.Code, http.StatusServiceUnavailable, response.Body.String())
	}
	var exhaustedCount int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM applications WHERE user_id = $1 AND club_id = $2", exhaustedApplicant.userID, clubA).Scan(&exhaustedCount); err != nil {
		t.Fatal(err)
	}
	if exhaustedCount != 0 {
		t.Fatalf("repeated deadlock created %d applications, want 0", exhaustedCount)
	}
	if _, err := db.ExecContext(ctx, "DROP TRIGGER raise_deadlock_once ON applications; DROP FUNCTION raise_deadlock_once(); DROP SEQUENCE application_deadlock_test_sequence"); err != nil {
		t.Fatal(err)
	}

	if _, err := db.ExecContext(ctx, "UPDATE clubs SET status = 'archived', archived_at = now() WHERE id = $1", clubA); err != nil {
		t.Fatal(err)
	}
	ownerRead := applicationAPIRequest(handler, service, &applicantA, http.MethodGet, "/api/applications/"+firstApplication.ID, "", "", "")
	if ownerRead.Code != http.StatusOK {
		t.Fatalf("owner read after club archive status = %d, want %d", ownerRead.Code, http.StatusOK)
	}
	if response := applicationAPIRequest(handler, service, &adminA, http.MethodGet, "/api/applications/"+firstApplication.ID, "", "", ""); response.Code != http.StatusNotFound {
		t.Fatalf("administrator read after club archive status = %d, want %d", response.Code, http.StatusNotFound)
	}
	if response := submit(rollbackApplicant, clubA, "archived club"); response.Code != http.StatusConflict {
		t.Fatalf("submission to archived club status = %d, want %d", response.Code, http.StatusConflict)
	}
	if response := changeMember(adminA, http.MethodPut, clubA, applicantB.userID, ""); response.Code != http.StatusConflict {
		t.Fatalf("membership change in archived club status = %d, want %d", response.Code, http.StatusConflict)
	}
	if response := requestDecision(adminA, rollbackApplication.ID, "approved"); response.Code != http.StatusNotFound {
		t.Fatalf("decision in archived club status = %d, want %d", response.Code, http.StatusNotFound)
	}
	adminList = applicationAPIRequest(handler, service, &adminA, http.MethodGet, "/api/applications", "", "", "")
	if err := json.Unmarshal(adminList.Body.Bytes(), &adminApplications); err != nil {
		t.Fatal(err)
	}
	if len(adminApplications) != 1 || adminApplications[0].ID != adminCrossClubApplication.ID {
		t.Fatalf("archived club administrator collection = %#v, want only own application", adminApplications)
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO applications (user_id, club_id, text, status, created_at)
		VALUES ($1, $2, 'legacy owner application', 'pending', now())`, rootID, clubB); err != nil {
		t.Fatal(err)
	}
	rootOwnApplications := applicationAPIRequest(handler, service, &rootToken, http.MethodGet, "/api/applications", "", "", "")
	if rootOwnApplications.Code != http.StatusOK {
		t.Fatalf("SuperUser owner collection status = %d", rootOwnApplications.Code)
	}
	var rootApplications []applicationRecord
	if err := json.Unmarshal(rootOwnApplications.Body.Bytes(), &rootApplications); err != nil {
		t.Fatal(err)
	}
	if len(rootApplications) != 1 || rootApplications[0].UserID != rootID {
		t.Fatalf("SuperUser owner collection = %#v, want only own application", rootApplications)
	}
}

func loginTestSession(ctx context.Context, service *Service, login, password string) (applicationTestSession, error) {
	userID, raw, csrf, err := service.Login(ctx, login, password, "")
	if err != nil {
		return applicationTestSession{}, err
	}
	return applicationTestSession{
		userID: userID,
		cookie: base64.RawURLEncoding.EncodeToString(raw),
		csrf:   base64.RawURLEncoding.EncodeToString(csrf),
	}, nil
}

func applicationAPIRequest(handler http.Handler, service *Service, session *applicationTestSession, method, target, body, origin, csrf string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	if session != nil && session.cookie != "" {
		request.AddCookie(&http.Cookie{Name: service.CookieName(), Value: session.cookie})
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertMembershipCount(t *testing.T, ctx context.Context, db *sql.DB, userID, clubID string, want int) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM club_memberships WHERE user_id = $1 AND club_id = $2", userID, clubID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("membership count for user %s in club %s = %d, want %d", userID, clubID, count, want)
	}
}
