package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func assertCursorPagination[T any](t *testing.T, request func(string) *httptest.ResponseRecorder, path string, id func(T) string) {
	t.Helper()
	firstResponse := request(path + "?limit=1")
	if firstResponse.Code != http.StatusOK {
		t.Fatalf("first page status = %d; body=%s", firstResponse.Code, firstResponse.Body.String())
	}
	var first []T
	if err := json.Unmarshal(firstResponse.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 {
		t.Fatalf("first page contains %d records, want 1", len(first))
	}
	cursor := firstResponse.Header().Get("X-Next-Cursor")
	if cursor == "" {
		t.Fatal("first page did not include a cursor despite additional fixture records")
	}
	secondResponse := request(path + "?limit=1&cursor=" + url.QueryEscape(cursor))
	if secondResponse.Code != http.StatusOK {
		t.Fatalf("second page status = %d; body=%s", secondResponse.Code, secondResponse.Body.String())
	}
	var second []T
	if err := json.Unmarshal(secondResponse.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || id(first[0]) == id(second[0]) {
		t.Fatalf("cursor pages have missing or repeated records: first=%#v second=%#v", first, second)
	}
}
