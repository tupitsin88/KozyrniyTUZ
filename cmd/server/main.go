package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
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
	server := newHTTPServer(address, newHandler(auth.NewHTTPHandler(authService)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return serveHTTP(ctx, server)
}

func newHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

func serveHTTP(ctx context.Context, server *http.Server) error {
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("listen HTTP: %w", err)
	}

	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.Serve(listener)
	}()

	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			<-serveErrors
			return fmt.Errorf("shut down HTTP server: %w", err)
		}
		if err := <-serveErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTP: %w", err)
		}
		return nil
	}
}
