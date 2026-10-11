package auth

import (
	"net/url"
	"testing"
	"time"
)

func TestParsePageRequestValidatesBoundedParameters(t *testing.T) {
	page, err := parsePageRequest(url.Values{})
	if err != nil || page.Limit != defaultPageSize || page.Cursor != nil {
		t.Fatalf("default page = %#v, %v", page, err)
	}
	for _, query := range []string{
		"limit=0", "limit=101", "limit=abc", "user_id=00000000-0000-4000-8000-000000000001",
		"limit=10&limit=20", "limit=", "cursor=", "cursor=invalid",
	} {
		values, _ := url.ParseQuery(query)
		if _, err := parsePageRequest(values); err == nil {
			t.Errorf("parsePageRequest(%q) succeeded, want error", query)
		}
	}
	if _, err := parsePaginationQuery("limit=%ZZ"); err == nil {
		t.Fatal("malformed URL query was accepted")
	}
}

func TestPageCursorRoundTripsAndRejectsInvalidTime(t *testing.T) {
	want := pageCursor{Key: time.Date(2026, 10, 11, 12, 13, 14, 123456789, time.UTC).Format(time.RFC3339Nano), ID: "8a4af8cf-49cc-4e42-a5bb-01e73b1c5200"}
	encoded := encodePageCursor(want.Key, want.ID)
	page, err := parsePageRequest(url.Values{"cursor": {encoded}, "limit": {"25"}})
	if err != nil || page.Limit != 25 || *page.Cursor != want {
		t.Fatalf("decoded page = %#v, %v; want %#v", page, err, want)
	}
	if _, err := parseTimeCursor(page.Cursor); err != nil {
		t.Fatalf("parse valid time cursor: %v", err)
	}
	page.Cursor.Key = "not-a-time"
	if _, err := parseTimeCursor(page.Cursor); err == nil {
		t.Fatal("invalid time cursor was accepted")
	}
}

func TestFinishPageReturnsStableCursorOnlyWhenMoreRowsExist(t *testing.T) {
	items := []clubSummary{
		{ID: "8a4af8cf-49cc-4e42-a5bb-01e73b1c5200", CreatedAt: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)},
		{ID: "8a4af8cf-49cc-4e42-a5bb-01e73b1c5201", CreatedAt: time.Date(2026, 10, 11, 11, 0, 0, 0, time.UTC)},
	}
	page := finishPage(items, 1, func(item clubSummary) pageCursor {
		return pageCursor{Key: item.CreatedAt.Format(time.RFC3339Nano), ID: item.ID}
	})
	if len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("non-final page = %#v, want one item and next cursor", page)
	}
	last := finishPage(items[:1], 1, func(item clubSummary) pageCursor {
		return pageCursor{Key: item.CreatedAt.Format(time.RFC3339Nano), ID: item.ID}
	})
	if len(last.Items) != 1 || last.NextCursor != "" {
		t.Fatalf("final page = %#v, want one item without cursor", last)
	}
}
