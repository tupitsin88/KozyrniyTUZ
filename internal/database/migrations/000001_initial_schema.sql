CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    login TEXT NOT NULL UNIQUE,
    password_verifier TEXT NOT NULL,
    global_role TEXT NOT NULL CHECK (global_role IN ('User', 'SuperUser')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX users_single_superuser
    ON users ((global_role))
    WHERE global_role = 'SuperUser';

CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    csrf_token BYTEA NOT NULL CHECK (octet_length(csrf_token) >= 32),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CHECK (last_seen_at >= created_at),
    CHECK (last_seen_at < expires_at),
    CHECK (expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX user_sessions_by_user
    ON user_sessions (user_id, created_at DESC);

CREATE INDEX user_sessions_by_expiry
    ON user_sessions (expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE clubs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    creator_id UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    archived_at TIMESTAMPTZ,
    CHECK (
        (status = 'active' AND archived_at IS NULL)
        OR (status = 'archived' AND archived_at IS NOT NULL AND archived_at >= created_at)
    )
);

CREATE INDEX clubs_active_order
    ON clubs (created_at DESC, id)
    WHERE status = 'active';

CREATE TABLE club_administrators (
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    club_id UUID NOT NULL REFERENCES clubs (id) ON DELETE RESTRICT,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, club_id)
);

CREATE INDEX club_administrators_by_club
    ON club_administrators (club_id, user_id);

CREATE TABLE club_memberships (
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    club_id UUID NOT NULL REFERENCES clubs (id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, club_id)
);

CREATE INDEX club_memberships_by_club
    ON club_memberships (club_id, user_id);

CREATE TABLE applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    club_id UUID NOT NULL REFERENCES clubs (id) ON DELETE RESTRICT,
    text TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    administrator_id UUID REFERENCES users (id) ON DELETE RESTRICT,
    decided_at TIMESTAMPTZ,
    CHECK (
        (status = 'pending' AND administrator_id IS NULL AND decided_at IS NULL)
        OR (status IN ('approved', 'rejected') AND administrator_id IS NOT NULL AND decided_at IS NOT NULL AND decided_at >= created_at)
    )
);

CREATE UNIQUE INDEX applications_one_pending_per_user_club
    ON applications (user_id, club_id)
    WHERE status = 'pending';

CREATE INDEX applications_by_user
    ON applications (user_id, created_at DESC, id);

CREATE INDEX applications_by_club_status
    ON applications (club_id, status, created_at, id);

CREATE TABLE materials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    club_id UUID NOT NULL REFERENCES clubs (id) ON DELETE RESTRICT,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (updated_at >= created_at)
);

CREATE INDEX materials_by_club
    ON materials (club_id, created_at DESC, id);
