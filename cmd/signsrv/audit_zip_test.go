package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// auditZip pulls the audit package for an envelope and returns its entries by
// name, so a test can read the manifest next to the documents it lists.
func auditZip(t *testing.T, ts *httptest.Server, admin, envelopeID string) map[string][]byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet,
		ts.URL+"/api/v1/envelopes/"+envelopeID+"/audit.zip", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+admin)
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("audit.zip: status %d body %s", res.StatusCode, body)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = b
	}
	return out
}

// zipNames is just the entry list, for the test that only checks which files
// the archive carries.
func zipNames(entries map[string][]byte) []string {
	out := make([]string, 0, len(entries))
	for name := range entries {
		out = append(out, name)
	}
	return out
}

// strOf renders a JSON value as a string, whether the server sent it as a

// decodeJSONMap decodes a response body into a map, tolerating an empty body
// so a test can read the shape without checking for it first.
// mintClientToken creates a machine client with the given scopes and returns a
// session token minted from its key. The key is not a bearer token — only a
// token exchanged for it is — which is what the scope tests need.
func mintClientToken(t *testing.T, ts *httptest.Server, admin, name, scopes string) string {
	t.Helper()
	code, out := adminCode(t, ts, http.MethodPost, "/api/v1/admin/clients", admin,
		`{"name":"`+name+`","scopes":["`+scopes+`"]}`)
	if code != http.StatusCreated {
		t.Fatalf("create client %s: code %d", name, code)
	}
	key, _ := out["key"].(string)
	if key == "" {
		t.Fatalf("create client returned no key: %v", out)
	}
	code, out = post(t, ts, "/api/v1/auth/token", `{"key":"`+key+`"}`, "")
	if code != http.StatusOK {
		t.Fatalf("token for client %s: code %d", name, code)
	}
	token, _ := out["access"].(string)
	if token == "" {
		t.Fatalf("token mint returned no access token: %v", out)
	}
	return token
}

func decodeJSONMap(b []byte) map[string]any {
	out := map[string]any{}
	if len(b) > 0 {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

// string or as a number.
func strOf(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatInt(int64(t), 10)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}
