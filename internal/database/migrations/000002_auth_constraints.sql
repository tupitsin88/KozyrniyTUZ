ALTER TABLE users
    ADD CONSTRAINT users_login_format
    CHECK (login = lower(login) AND login ~ '^[a-z0-9._-]{3,64}$');

ALTER TABLE user_sessions
    ADD CONSTRAINT user_sessions_csrf_token_length
    CHECK (octet_length(csrf_token) = 32);
