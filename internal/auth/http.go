package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

const maxRequestBody = 16 * 1024

type HTTPHandler struct {
	service *Service
}

type credentials struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type authResponse struct {
	Authenticated bool   `json:"authenticated"`
	CSRFToken     string `json:"csrf_token"`
}

func NewHTTPHandler(service *Service) http.Handler {
	handler := &HTTPHandler{service: service}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/register", handler.register)
	mux.HandleFunc("/api/login", handler.login)
	mux.HandleFunc("/api/session", handler.session)
	mux.HandleFunc("/api/logout", handler.logout)
	return securityHeaders(mux)
}

func (h *HTTPHandler) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !h.requireOrigin(w, r) || !requireJSON(w, r) {
		return
	}
	var input credentials
	if !decodeJSON(w, r, &input) {
		return
	}
	oldToken := ""
	if cookie, err := r.Cookie(h.service.CookieName()); err == nil {
		oldToken = cookie.Value
	}
	_, raw, csrf, err := h.service.Register(r.Context(), input.Login, input.Password, oldToken)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidInput):
			writeError(w, http.StatusBadRequest, "invalid registration data")
		case errors.Is(err, ErrLoginExists):
			writeError(w, http.StatusConflict, "login is unavailable")
		default:
			writeError(w, http.StatusInternalServerError, "request failed")
		}
		return
	}
	h.setSessionCookie(w, raw)
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, authResponse{Authenticated: true, CSRFToken: base64.RawURLEncoding.EncodeToString(csrf)})
}

func (h *HTTPHandler) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !h.requireOrigin(w, r) || !requireJSON(w, r) {
		return
	}
	var input credentials
	if !decodeJSON(w, r, &input) {
		return
	}
	oldToken := ""
	if cookie, err := r.Cookie(h.service.CookieName()); err == nil {
		oldToken = cookie.Value
	}
	_, raw, csrf, err := h.service.Login(r.Context(), input.Login, input.Password, oldToken)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidCredentials):
			writeError(w, http.StatusUnauthorized, "invalid login or password")
		case errors.Is(err, ErrInvalidInput):
			writeError(w, http.StatusUnauthorized, "invalid login or password")
		default:
			writeError(w, http.StatusInternalServerError, "request failed")
		}
		return
	}
	h.setSessionCookie(w, raw)
	writeJSON(w, authResponse{Authenticated: true, CSRFToken: base64.RawURLEncoding.EncodeToString(csrf)})
}

func (h *HTTPHandler) session(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	origins := r.Header.Values("Origin")
	if len(origins) > 1 || (len(origins) == 1 && origins[0] != h.service.TrustedOrigin()) {
		writeError(w, http.StatusForbidden, "origin is not allowed")
		return
	}
	principal, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if err := h.service.Touch(r.Context(), principal); err != nil {
		if errors.Is(err, ErrSessionInvalid) {
			writeError(w, http.StatusUnauthorized, "authentication required")
		} else {
			writeError(w, http.StatusInternalServerError, "request failed")
		}
		return
	}
	writeJSON(w, authResponse{Authenticated: true, CSRFToken: base64.RawURLEncoding.EncodeToString(principal.CSRF)})
}

func (h *HTTPHandler) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !h.requireOrigin(w, r) {
		return
	}
	cookie, err := r.Cookie(h.service.CookieName())
	if err != nil || cookie.Value == "" {
		h.clearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	principal, err := h.service.Authenticate(r.Context(), cookie.Value)
	if errors.Is(err, ErrSessionInvalid) {
		h.clearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "request failed")
		return
	}
	if !csrfMatches(r.Header.Get("X-CSRF-Token"), principal.CSRF) {
		writeError(w, http.StatusForbidden, "CSRF validation failed")
		return
	}
	if err := h.service.Revoke(r.Context(), principal); err != nil {
		writeError(w, http.StatusInternalServerError, "request failed")
		return
	}
	h.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *HTTPHandler) authenticate(w http.ResponseWriter, r *http.Request) (Principal, bool) {
	cookie, err := r.Cookie(h.service.CookieName())
	if err != nil || cookie.Value == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return Principal{}, false
	}
	principal, err := h.service.Authenticate(r.Context(), cookie.Value)
	if errors.Is(err, ErrSessionInvalid) {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return Principal{}, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "request failed")
		return Principal{}, false
	}
	return principal, true
}

func (h *HTTPHandler) requireOrigin(w http.ResponseWriter, r *http.Request) bool {
	origins := r.Header.Values("Origin")
	if len(origins) != 1 || origins[0] != h.service.TrustedOrigin() {
		writeError(w, http.StatusForbidden, "origin is not allowed")
		return false
	}
	return true
}

func requireJSON(w http.ResponseWriter, r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "application/json is required")
		return false
	}
	return true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

func (h *HTTPHandler) setSessionCookie(w http.ResponseWriter, raw []byte) {
	http.SetCookie(w, &http.Cookie{
		Name: h.service.CookieName(), Value: base64.RawURLEncoding.EncodeToString(raw),
		Path: "/", HttpOnly: true, Secure: h.service.CookieSecure(), SameSite: http.SameSiteLaxMode,
		MaxAge: int(h.service.absoluteTimeout.Seconds()),
	})
}

func (h *HTTPHandler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: h.service.CookieName(), Value: "", Path: "/", HttpOnly: true,
		Secure: h.service.CookieSecure(), SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	writeJSON(w, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, body any) {
	_ = json.NewEncoder(w).Encode(body)
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func csrfMatches(provided string, expected []byte) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(provided)
	return err == nil && len(decoded) == len(expected) && subtle.ConstantTimeCompare(decoded, expected) == 1
}
