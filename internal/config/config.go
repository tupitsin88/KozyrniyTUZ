package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"
)

const (
	defaultPort              = "8080"
	defaultDBMaxOpenConns    = 20
	defaultDBMaxIdleConns    = 5
	defaultDBConnMaxLifetime = 30 * time.Minute
	defaultDBConnMaxIdleTime = 5 * time.Minute
	defaultTrustedOrigin     = "http://localhost:8080"
	defaultSessionIdle       = 30 * time.Minute
	defaultSessionAbsolute   = 12 * time.Hour
	defaultArgonMemory       = uint32(19 * 1024)
	defaultArgonIterations   = uint32(2)
	defaultArgonParallelism  = uint8(1)
)

type Config struct {
	Port              string
	DatabaseURL       string
	DBMaxOpenConns    int
	DBMaxIdleConns    int
	DBConnMaxLifetime time.Duration
	DBConnMaxIdleTime time.Duration
	TrustedOrigin     string
	BootstrapLogin    string
	BootstrapPassword string
	SessionIdle       time.Duration
	SessionAbsolute   time.Duration
	ArgonMemory       uint32
	ArgonIterations   uint32
	ArgonParallelism  uint8
}

func Load() (Config, error) {
	port := envOrDefault("PORT", defaultPort)
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return Config{}, fmt.Errorf("PORT must be a number between 1 and 65535")
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}

	maxOpen, err := intEnvOrDefault("DB_MAX_OPEN_CONNS", defaultDBMaxOpenConns)
	if err != nil || maxOpen < 1 {
		return Config{}, fmt.Errorf("DB_MAX_OPEN_CONNS must be a positive integer")
	}

	maxIdle, err := intEnvOrDefault("DB_MAX_IDLE_CONNS", defaultDBMaxIdleConns)
	if err != nil || maxIdle < 0 || maxIdle > maxOpen {
		return Config{}, fmt.Errorf("DB_MAX_IDLE_CONNS must be between 0 and DB_MAX_OPEN_CONNS")
	}

	trustedOrigin := envOrDefault("TRUSTED_ORIGIN", defaultTrustedOrigin)
	if err := validateOrigin(trustedOrigin); err != nil {
		return Config{}, err
	}

	sessionIdle, err := durationEnvOrDefault("SESSION_IDLE_TIMEOUT", defaultSessionIdle)
	if err != nil || sessionIdle < time.Minute || sessionIdle > 24*time.Hour {
		return Config{}, fmt.Errorf("SESSION_IDLE_TIMEOUT must be between 1m and 24h")
	}
	sessionAbsolute, err := durationEnvOrDefault("SESSION_ABSOLUTE_TIMEOUT", defaultSessionAbsolute)
	if err != nil || sessionAbsolute < sessionIdle || sessionAbsolute > 30*24*time.Hour {
		return Config{}, fmt.Errorf("SESSION_ABSOLUTE_TIMEOUT must be at least SESSION_IDLE_TIMEOUT and no more than 720h")
	}

	argonMemory, err := uint32EnvOrDefault("ARGON2_MEMORY_KIB", defaultArgonMemory)
	if err != nil || argonMemory < 19*1024 || argonMemory > 64*1024 {
		return Config{}, fmt.Errorf("ARGON2_MEMORY_KIB must be between 19456 and 65536")
	}
	argonIterations, err := uint32EnvOrDefault("ARGON2_ITERATIONS", defaultArgonIterations)
	if err != nil || argonIterations < 2 || argonIterations > 4 {
		return Config{}, fmt.Errorf("ARGON2_ITERATIONS must be between 2 and 4")
	}
	argonParallelism, err := uint8EnvOrDefault("ARGON2_PARALLELISM", defaultArgonParallelism)
	if err != nil || argonParallelism < 1 || argonParallelism > 4 {
		return Config{}, fmt.Errorf("ARGON2_PARALLELISM must be between 1 and 4")
	}

	return Config{
		Port:              port,
		DatabaseURL:       databaseURL,
		DBMaxOpenConns:    maxOpen,
		DBMaxIdleConns:    maxIdle,
		DBConnMaxLifetime: defaultDBConnMaxLifetime,
		DBConnMaxIdleTime: defaultDBConnMaxIdleTime,
		TrustedOrigin:     trustedOrigin,
		BootstrapLogin:    os.Getenv("BOOTSTRAP_SUPERUSER_LOGIN"),
		BootstrapPassword: os.Getenv("BOOTSTRAP_SUPERUSER_PASSWORD"),
		SessionIdle:       sessionIdle,
		SessionAbsolute:   sessionAbsolute,
		ArgonMemory:       argonMemory,
		ArgonIterations:   argonIterations,
		ArgonParallelism:  argonParallelism,
	}, nil
}

func envOrDefault(name, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func intEnvOrDefault(name string, fallback int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	return strconv.Atoi(value)
}

func durationEnvOrDefault(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	return time.ParseDuration(value)
}

func uint32EnvOrDefault(name string, fallback uint32) (uint32, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	return uint32(parsed), err
}

func uint8EnvOrDefault(name string, fallback uint8) (uint8, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 8)
	return uint8(parsed), err
}

func validateOrigin(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return fmt.Errorf("TRUSTED_ORIGIN must be an exact http or https origin without a path")
	}
	if parsed.String() != value || parsed.Hostname() == "" {
		return fmt.Errorf("TRUSTED_ORIGIN must be a canonical exact origin")
	}
	if port := parsed.Port(); port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || strconv.Itoa(portNumber) != port || portNumber < 1 || portNumber > 65535 || (parsed.Scheme == "http" && portNumber == 80) || (parsed.Scheme == "https" && portNumber == 443) {
			return fmt.Errorf("TRUSTED_ORIGIN must use a valid non-default port")
		}
	}
	return nil
}
