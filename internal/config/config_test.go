package config

import "testing"

func TestLoadDefaultsForSecuritySettings(t *testing.T) {
	t.Setenv("PORT", "8080")
	t.Setenv("DATABASE_URL", "postgres://user:password@localhost:5432/app?sslmode=disable")
	t.Setenv("DB_MAX_OPEN_CONNS", "20")
	t.Setenv("DB_MAX_IDLE_CONNS", "5")
	t.Setenv("TRUSTED_ORIGIN", "http://localhost:8080")
	for _, name := range []string{
		"SESSION_IDLE_TIMEOUT", "SESSION_ABSOLUTE_TIMEOUT",
		"ARGON2_MEMORY_KIB", "ARGON2_ITERATIONS", "ARGON2_PARALLELISM",
	} {
		t.Setenv(name, "")
	}
	settings, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if settings.SessionIdle.String() != "30m0s" || settings.SessionAbsolute.String() != "12h0m0s" {
		t.Fatalf("unexpected session timeouts: idle=%s absolute=%s", settings.SessionIdle, settings.SessionAbsolute)
	}
	if settings.ArgonMemory != 19456 || settings.ArgonIterations != 2 || settings.ArgonParallelism != 1 {
		t.Fatalf("unexpected Argon2id settings: %#v", settings)
	}
}

func TestLoadRejectsUnsafeSecuritySettings(t *testing.T) {
	base := map[string]string{
		"PORT": "8080", "DATABASE_URL": "postgres://user:password@localhost:5432/app?sslmode=disable",
		"DB_MAX_OPEN_CONNS": "20", "DB_MAX_IDLE_CONNS": "5", "TRUSTED_ORIGIN": "http://localhost:8080",
		"SESSION_IDLE_TIMEOUT": "30m", "SESSION_ABSOLUTE_TIMEOUT": "12h",
		"ARGON2_MEMORY_KIB": "19456", "ARGON2_ITERATIONS": "2", "ARGON2_PARALLELISM": "1",
	}
	cases := []struct{ name, value string }{
		{"TRUSTED_ORIGIN", "http://localhost:8080/path"},
		{"TRUSTED_ORIGIN", "null"},
		{"TRUSTED_ORIGIN", "http://localhost:80"},
		{"TRUSTED_ORIGIN", "https://localhost:443"},
		{"TRUSTED_ORIGIN", "http://localhost:8080?"},
		{"TRUSTED_ORIGIN", "http://localhost:08080"},
		{"SESSION_IDLE_TIMEOUT", "0s"},
		{"SESSION_ABSOLUTE_TIMEOUT", "1m"},
		{"ARGON2_MEMORY_KIB", "1024"},
		{"ARGON2_ITERATIONS", "99"},
		{"ARGON2_PARALLELISM", "0"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name+"="+testCase.value, func(t *testing.T) {
			for name, value := range base {
				t.Setenv(name, value)
			}
			t.Setenv(testCase.name, testCase.value)
			if _, err := Load(); err == nil {
				t.Fatal("unsafe security configuration was accepted")
			}
		})
	}
}
