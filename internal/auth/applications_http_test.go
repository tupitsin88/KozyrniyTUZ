package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUUIDValidation(t *testing.T) {
	for _, testCase := range []struct {
		value string
		valid bool
	}{
		{value: "8a4af8cf-49cc-4e42-a5bb-01e73b1c5200", valid: true},
		{value: "8A4AF8CF-49CC-4E42-A5BB-01E73B1C5200", valid: true},
		{value: "8a4af8cf49cc4e42a5bb01e73b1c5200", valid: false},
		{value: "8a4af8cf-49cc-4e42-a5bb-01e73b1c520x", valid: false},
		{value: "8a4af8cf-49cc-4e42-a5bb-01e73b1c5200/decision", valid: false},
	} {
		if got := isUUID(testCase.value); got != testCase.valid {
			t.Errorf("isUUID(%q) = %t, want %t", testCase.value, got, testCase.valid)
		}
	}
}

func TestApplicationRoutesRejectUntrustedFiltersAndMalformedPaths(t *testing.T) {
	handler := NewHTTPHandler(&Service{trustedOrigin: "http://localhost:8080", cookieName: "club-session"})
	cases := []struct {
		name       string
		method     string
		target     string
		wantStatus int
		wantAllow  string
	}{
		{name: "foreign user filter", method: http.MethodGet, target: "/api/applications?user_id=8a4af8cf-49cc-4e42-a5bb-01e73b1c5200", wantStatus: http.StatusBadRequest},
		{name: "malformed application identifier", method: http.MethodGet, target: "/api/applications/not-a-uuid", wantStatus: http.StatusNotFound},
		{name: "malformed decision identifier", method: http.MethodPost, target: "/api/applications/not-a-uuid/decision", wantStatus: http.StatusNotFound},
		{name: "unsupported application method", method: http.MethodDelete, target: "/api/applications", wantStatus: http.StatusMethodNotAllowed, wantAllow: "GET, POST"},
		{name: "unsupported decision method", method: http.MethodGet, target: "/api/applications/8a4af8cf-49cc-4e42-a5bb-01e73b1c5200/decision", wantStatus: http.StatusMethodNotAllowed, wantAllow: http.MethodPost},
		{name: "membership query override", method: http.MethodPut, target: "/api/clubs/8a4af8cf-49cc-4e42-a5bb-01e73b1c5200/members/8a4af8cf-49cc-4e42-a5bb-01e73b1c5201?user_id=8a4af8cf-49cc-4e42-a5bb-01e73b1c5202", wantStatus: http.StatusBadRequest},
		{name: "malformed club archive identifier", method: http.MethodDelete, target: "/api/clubs/not-a-uuid", wantStatus: http.StatusNotFound},
		{name: "malformed material club identifier", method: http.MethodGet, target: "/api/clubs/not-a-uuid/materials", wantStatus: http.StatusNotFound},
		{name: "malformed material identifier", method: http.MethodGet, target: "/api/materials/not-a-uuid", wantStatus: http.StatusNotFound},
		{name: "material query override", method: http.MethodGet, target: "/api/materials/8a4af8cf-49cc-4e42-a5bb-01e73b1c5200?club_id=8a4af8cf-49cc-4e42-a5bb-01e73b1c5201", wantStatus: http.StatusBadRequest},
		{name: "unsupported archive method", method: http.MethodPost, target: "/api/clubs/8a4af8cf-49cc-4e42-a5bb-01e73b1c5200", wantStatus: http.StatusMethodNotAllowed, wantAllow: http.MethodDelete},
		{name: "unsupported material update method", method: http.MethodDelete, target: "/api/materials/8a4af8cf-49cc-4e42-a5bb-01e73b1c5200", wantStatus: http.StatusMethodNotAllowed, wantAllow: "GET, PUT"},
		{name: "member list query override", method: http.MethodGet, target: "/api/clubs/8a4af8cf-49cc-4e42-a5bb-01e73b1c5200/members?user_id=8a4af8cf-49cc-4e42-a5bb-01e73b1c5201", wantStatus: http.StatusBadRequest},
		{name: "unsupported member collection method", method: http.MethodDelete, target: "/api/clubs/8a4af8cf-49cc-4e42-a5bb-01e73b1c5200/members", wantStatus: http.StatusMethodNotAllowed, wantAllow: "GET, POST"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(testCase.method, testCase.target, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != testCase.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, testCase.wantStatus, response.Body.String())
			}
			if testCase.wantAllow != "" && response.Header().Get("Allow") != testCase.wantAllow {
				t.Fatalf("Allow = %q, want %q", response.Header().Get("Allow"), testCase.wantAllow)
			}
		})
	}
}
