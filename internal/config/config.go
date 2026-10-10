package config

import (
	"fmt"
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
)

type Config struct {
	Port              string
	DatabaseURL       string
	DBMaxOpenConns    int
	DBMaxIdleConns    int
	DBConnMaxLifetime time.Duration
	DBConnMaxIdleTime time.Duration
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

	return Config{
		Port:              port,
		DatabaseURL:       databaseURL,
		DBMaxOpenConns:    maxOpen,
		DBMaxIdleConns:    maxIdle,
		DBConnMaxLifetime: defaultDBConnMaxLifetime,
		DBConnMaxIdleTime: defaultDBConnMaxIdleTime,
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
