package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/tupitsin88/KozyrniyTUZ/internal/config"
	"github.com/tupitsin88/KozyrniyTUZ/internal/database"
)

type healthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
}

func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
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

	address := ":" + settings.Port
	log.Printf("club-membership API listening on %s", address)
	if err := http.ListenAndServe(address, newHandler()); err != nil {
		return fmt.Errorf("serve HTTP: %w", err)
	}
	return nil
}
