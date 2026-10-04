package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

const defaultPort = "8080"

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
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	address := ":" + port
	log.Printf("club-membership API listening on %s", address)
	log.Fatal(http.ListenAndServe(address, newHandler()))
}
