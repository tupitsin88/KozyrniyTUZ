package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRegistrationRequiresTrustedOriginAndStrictJSON(t *testing.T) {
	service := &Service{trustedOrigin: "http://localhost:8080", cookieName: "club-session"}
	handler := NewHTTPHandler(service)

	cases := []struct {
		name        string
		origin      string
		contentType string
		body        string
		status      int
	}{
		{name: "missing origin", contentType: "application/json", body: `{"login":"alice","password":"correct horse battery staple"}`, status: http.StatusForbidden},
		{name: "null origin", origin: "null", contentType: "application/json", body: `{"login":"alice","password":"correct horse battery staple"}`, status: http.StatusForbidden},
		{name: "different port", origin: "http://localhost:8081", contentType: "application/json", body: `{"login":"alice","password":"correct horse battery staple"}`, status: http.StatusForbidden},
		{name: "non JSON", origin: "http://localhost:8080", contentType: "text/plain", body: `{"login":"alice","password":"correct horse battery staple"}`, status: http.StatusUnsupportedMediaType},
		{name: "role assignment", origin: "http://localhost:8080", contentType: "application/json", body: `{"login":"alice","password":"correct horse battery staple","global_role":"SuperUser"}`, status: http.StatusBadRequest},
		{name: "unknown field", origin: "http://localhost:8080", contentType: "application/json", body: `{"login":"alice","password":"correct horse battery staple","extra":true}`, status: http.StatusBadRequest},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/register", strings.NewReader(testCase.body))
			request.Header.Set("Origin", testCase.origin)
			request.Header.Set("Content-Type", testCase.contentType)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != testCase.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, testCase.status, response.Body.String())
			}
		})
	}
}

func TestRegistrationRejectsMultipleOriginHeaders(t *testing.T) {
	service := &Service{trustedOrigin: "http://localhost:8080", cookieName: "club-session"}
	handler := NewHTTPHandler(service)
	request := httptest.NewRequest(http.MethodPost, "/api/register", strings.NewReader(`{"login":"alice","password":"correct horse battery staple"}`))
	request.Header.Add("Origin", "http://localhost:8080")
	request.Header.Add("Origin", "http://evil.example")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestCSRFTokenEncodingAndComparison(t *testing.T) {
	expected := []byte("01234567890123456789012345678901")
	encoded := "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE"
	if !csrfMatches(encoded, expected) {
		t.Fatal("matching CSRF token was rejected")
	}
	if csrfMatches(encoded+"x", expected) || csrfMatches("", expected) {
		t.Fatal("incorrect CSRF token was accepted")
	}
}

func TestProductionSessionCookieAttributes(t *testing.T) {
	service := &Service{cookieName: "__Host-session", cookieSecure: true, absoluteTimeout: 12 * time.Hour}
	handler := &HTTPHandler{service: service}
	response := httptest.NewRecorder()
	handler.setSessionCookie(response, make([]byte, 32))
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != "__Host-session" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge != int((12*time.Hour).Seconds()) {
		t.Fatalf("production session cookie has unsafe attributes: %#v", cookie)
	}
}
