package auth

import (
	"context"
	"fmt"
	"time"
)

const (
	sessionCleanupRetention  = 30 * 24 * time.Hour
	sessionCleanupBatchSize  = 500
	sessionCleanupMaxBatches = 10
	sessionCleanupInterval   = time.Hour
)

func (s *Service) CleanupExpiredSessions(ctx context.Context) (int64, error) {
	var total int64
	for range sessionCleanupMaxBatches {
		result, err := s.db.ExecContext(ctx, `
			DELETE FROM user_sessions
			WHERE ctid IN (
			    SELECT ctid
			    FROM user_sessions
			    WHERE (revoked_at IS NOT NULL AND revoked_at < now() - $1::interval)
			       OR (revoked_at IS NULL AND expires_at < now() - $1::interval)
			       OR (revoked_at IS NULL AND last_seen_at < now() - $1::interval - $2::interval)
			    ORDER BY created_at, id
			    LIMIT $3
			)`, sessionCleanupRetention.String(), s.idleTimeout.String(), sessionCleanupBatchSize)
		if err != nil {
			return total, fmt.Errorf("delete expired sessions: %w", err)
		}
		deleted, err := result.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("read deleted session count: %w", err)
		}
		total += deleted
		if deleted < sessionCleanupBatchSize {
			return total, nil
		}
	}
	return total, nil
}

func (s *Service) RunSessionCleanup(ctx context.Context, onError func(error)) {
	ticker := time.NewTicker(sessionCleanupInterval)
	defer ticker.Stop()
	for {
		cleanupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, err := s.CleanupExpiredSessions(cleanupCtx)
		cancel()
		if err != nil && ctx.Err() == nil && onError != nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
