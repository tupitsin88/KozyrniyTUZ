package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/tupitsin88/KozyrniyTUZ/internal/auth"
	"github.com/tupitsin88/KozyrniyTUZ/internal/config"
	"github.com/tupitsin88/KozyrniyTUZ/internal/database"
)

type healthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
}

func newHandler(authHandlers ...http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	if len(authHandlers) != 0 {
		mux.Handle("/api/", authHandlers[0])
	}
	return mux
}

func healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(healthResponse{
		Status:  "ok",
		Service: "club-membership",
	})
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	settings, err := config.Load()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := database.Open(ctx, settings.DatabaseURL, database.PoolConfig{
		MaxOpenConns:    settings.DBMaxOpenConns,
		MaxIdleConns:    settings.DBMaxIdleConns,
		ConnMaxLifetime: settings.DBConnMaxLifetime,
		ConnMaxIdleTime: settings.DBConnMaxIdleTime,
	})
	if err != nil {
		return err
	}
	defer db.Close()

	authService, err := auth.NewService(db, settings)
	if err != nil {
		return err
	}
	if err := authService.Bootstrap(ctx, settings.BootstrapLogin, settings.BootstrapPassword); err != nil {
		return err
	}
	settings.BootstrapPassword = ""
	settings.BootstrapLogin = ""

	address := ":" + settings.Port
	log.Printf("club-membership API listening on %s", address)
	if err := http.ListenAndServe(address, newHandler(auth.NewHTTPHandler(authService))); err != nil {
		return fmt.Errorf("serve HTTP: %w", err)
	}
	return nil
}
