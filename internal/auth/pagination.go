package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	defaultPageSize = 50
	maximumPageSize = 100
)

var errInvalidPagination = errors.New("invalid pagination parameters")

type pageCursor struct {
	Key string `json:"key"`
	ID  string `json:"id"`
}

type pageRequest struct {
	Limit  int
	Cursor *pageCursor
}

type pageResult[T any] struct {
	Items      []T
	NextCursor string
}

func parsePageRequest(query url.Values) (pageRequest, error) {
	for name, values := range query {
		if (name != "limit" && name != "cursor") || len(values) != 1 {
			return pageRequest{}, errInvalidPagination
		}
	}
	page := pageRequest{Limit: defaultPageSize}
	if values, exists := query["limit"]; exists {
		rawLimit := values[0]
		if rawLimit == "" {
			return pageRequest{}, errInvalidPagination
		}
		limit, err := strconv.Atoi(rawLimit)
		if err != nil || limit < 1 || limit > maximumPageSize {
			return pageRequest{}, errInvalidPagination
		}
		page.Limit = limit
	}
	if values, exists := query["cursor"]; exists {
		rawCursor := values[0]
		if rawCursor == "" {
			return pageRequest{}, errInvalidPagination
		}
		if len(rawCursor) > 512 {
			return pageRequest{}, errInvalidPagination
		}
		decoded, err := base64.RawURLEncoding.DecodeString(rawCursor)
		if err != nil {
			return pageRequest{}, errInvalidPagination
		}
		var cursor pageCursor
		decoder := json.NewDecoder(bytes.NewReader(decoded))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&cursor); err != nil || cursor.Key == "" || len(cursor.Key) > 128 || !isUUID(cursor.ID) {
			return pageRequest{}, errInvalidPagination
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return pageRequest{}, errInvalidPagination
		}
		page.Cursor = &cursor
	}
	return page, nil
}

func parsePaginationQuery(rawQuery string) (pageRequest, error) {
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return pageRequest{}, errInvalidPagination
	}
	return parsePageRequest(query)
}

func parseTimeCursor(cursor *pageCursor) (time.Time, error) {
	if cursor == nil {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, cursor.Key)
	if err != nil {
		return time.Time{}, errInvalidPagination
	}
	return parsed, nil
}

func nullableTime(cursor *pageCursor, parsed time.Time) any {
	if cursor == nil {
		return nil
	}
	return parsed
}

func encodePageCursor(key, id string) string {
	encoded, _ := json.Marshal(pageCursor{Key: key, ID: id})
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func finishPage[T any](items []T, limit int, cursorFor func(T) pageCursor) pageResult[T] {
	result := pageResult[T]{Items: items}
	if len(items) > limit {
		result.Items = items[:limit]
		last := result.Items[len(result.Items)-1]
		result.NextCursor = encodePageCursor(cursorFor(last).Key, cursorFor(last).ID)
	}
	return result
}

func writePage[T any](w http.ResponseWriter, page pageResult[T]) {
	if page.NextCursor != "" {
		w.Header().Set("X-Next-Cursor", page.NextCursor)
	}
	writeJSON(w, page.Items)
}
