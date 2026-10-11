CREATE INDEX user_sessions_by_revoked_at
    ON user_sessions (revoked_at, created_at, id)
    WHERE revoked_at IS NOT NULL;

CREATE INDEX user_sessions_by_idle_expiry
    ON user_sessions (last_seen_at, created_at, id)
    WHERE revoked_at IS NULL;
