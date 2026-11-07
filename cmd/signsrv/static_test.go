package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// The signing app is compiled into the binary. A phone that cached app.js must
// get the new one after a deploy, so the asset response carries an ETag of the
// file's own bytes, answers If-None-Match with 304, and is never reused without
// asking first (max-age=0, must-revalidate). Without this a signer runs the
// previous build until a max-age expires.
func TestStaticAssetETagRevalidation(t *testing.T) {
	ts := newTestServer(t, testConfig(t))

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/assets/spa/app.js", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	etag := res.Header.Get("ETag")
	if !strings.HasPrefix(etag, `"`) || len(etag) < 20 {
		t.Fatalf("app.js has no ETag: %q", etag)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", res.StatusCode)
	}
	if cc := res.Header.Get("Cache-Control"); !strings.Contains(cc, "must-revalidate") {
		t.Fatalf("app.js Cache-Control %q, want must-revalidate", cc)
	}

	// Same bytes, same ETag: the client may keep what it has.
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/assets/spa/app.js", nil)
	req2.Header.Set("If-None-Match", etag)
	res2, err := ts.Client().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusNotModified {
		t.Fatalf("If-None-Match got %d, want 304", res2.StatusCode)
	}

	// A stale ETag is a different file, so it is served in full.
	req3, _ := http.NewRequest(http.MethodGet, ts.URL+"/assets/spa/app.js", nil)
	req3.Header.Set("If-None-Match", `"deadbeef"`)
	res3, err := ts.Client().Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer res3.Body.Close()
	if res3.StatusCode != http.StatusOK {
		t.Fatalf("stale If-None-Match got %d, want 200", res3.StatusCode)
	}
}

// The page that loads the app points at a versioned asset URL. A phone that
// cached the previous build asked for /assets/spa/app.js; after a deploy the
// page asks for /assets/spa/app.js?v=<hash of the new bytes>, which is not in
// that cache, so the new build is used on the next open with no hard refresh.
// The versioned URL is the same embedded file.
func TestIndexHTMLCarriesVersionedAssetURLs(t *testing.T) {
	ts := newTestServer(t, testConfig(t))

	res, err := ts.Client().Get(ts.URL + "/s/7b3f2a91c4d5e6f7")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if cc := res.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("index.html Cache-Control %q, want no-store", cc)
	}
	for _, name := range []string{"app.js", "app.css"} {
		if !strings.Contains(string(body), "/assets/spa/"+name+"?v=") {
			t.Fatalf("index.html does not version %s:\n%s", name, body)
		}
	}
	if strings.Contains(string(body), `src="/assets/spa/app.js"`) {
		t.Fatal("index.html still carries an unversioned app.js reference")
	}

	res2, err := ts.Client().Get(ts.URL + "/assets/spa/app.js?v=deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("versioned asset got %d, want 200", res2.StatusCode)
	}
	got, err := io.ReadAll(res2.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "renderDocument") {
		t.Fatal("the versioned asset is not the app")
	}
}
