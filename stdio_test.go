package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

func TestStdioHealthRequest(t *testing.T) {
	s := makeTestServer(t)

	request := `{"id":"test-001","method":"health"}`
	stdin := bytes.NewBufferString(request + "\n")
	stdout := &bytes.Buffer{}

	stdioServer := newStdioServerWithIO(s, stdin, stdout)
	if err := stdioServer.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	var actual map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &actual); err != nil {
		t.Fatalf("Failed to parse response:\n%s\nError: %v", stdout.String(), err)
	}

	expected := map[string]interface{}{
		"id":      "test-001",
		"success": true,
		"code":    float64(200),
	}

	if diff := compareJSON(expected, actual); diff != "" {
		t.Errorf("Response mismatch:\n%s", diff)
	}
}

func makeTestServer(t *testing.T) *server {
	t.Helper()

	db, err := sqlx.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	s := &server{
		db:     db,
		router: mux.NewRouter(),
	}
	s.routes()

	return s
}

// compareJSON compares two JSON objects and returns a human-readable diff
func compareJSON(expected, actual map[string]interface{}) string {
	var diffs []string
	for key, expectedVal := range expected {
		actualVal, exists := actual[key]
		if !exists {
			diffs = append(diffs, fmt.Sprintf("  Missing field: %q", key))
			continue
		}
		if fmt.Sprintf("%v", expectedVal) != fmt.Sprintf("%v", actualVal) {
			diffs = append(diffs, fmt.Sprintf("  Field %q: expected %v, got %v", key, expectedVal, actualVal))
		}
	}

	if len(diffs) > 0 {
		expectedJSON, _ := json.MarshalIndent(expected, "    ", "  ")
		actualJSON, _ := json.MarshalIndent(actual, "    ", "  ")
		return fmt.Sprintf("Expected:\n    %s\n\n  Actual:\n    %s\n\n  Differences:\n%s",
			expectedJSON, actualJSON, strings.Join(diffs, "\n"))
	}

	return ""
}
