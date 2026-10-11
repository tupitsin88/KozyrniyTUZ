package auth

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

func TestCleanupExpiredSessionsPreservesDatabaseError(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://localhost/unused")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	service := &Service{db: db, idleTimeout: time.Minute}
	_, err = service.CleanupExpiredSessions(context.Background())
	if err == nil || !strings.Contains(err.Error(), "sql: database is closed") {
		t.Fatalf("cleanup error = %v, want underlying closed-database error", err)
	}
}
