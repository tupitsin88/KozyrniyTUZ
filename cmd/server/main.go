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
	webassets "github.com/tupitsin88/KozyrniyTUZ/web"
)

type healthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
}

func newHandler(authHandlers ...http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	mux.HandleFunc("/", frontend)
	if len(authHandlers) != 0 {
		mux.Handle("/api/", authHandlers[0])
	}
	return mux
}

func frontend(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var file string
	switch r.URL.Path {
	case "/":
		file = "static/index.html"
	case "/app.js":
		file = "static/app.js"
	case "/styles.css":
		file = "static/styles.css"
	default:
		http.NotFound(w, r)
		return
	}

	content, err := webassets.Files.ReadFile(file)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch file {
	case "static/index.html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case "static/app.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case "static/styles.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(content)
	}
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
