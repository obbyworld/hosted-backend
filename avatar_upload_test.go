package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func TestAvatarFilePrefixKeepsNamesInsideTheImagesFolder(t *testing.T) {
	for _, name := range []string{"#!/bin/bash", "#../../etc", `#a\b`, "#a?b#c%d"} {
		prefix := avatarFilePrefix("channel", name)
		if strings.ContainsAny(prefix, `/\.?#%`) {
			t.Errorf("prefix %q for %q is unsafe in a path or URL", prefix, name)
		}
	}
}

func TestAvatarFilePrefixKeepsOwnersApart(t *testing.T) {
	pairs := [][2]string{{"bob", "bob_x"}, {"#a/b", "#a_b"}}
	for _, pair := range pairs {
		a, b := avatarFilePrefix("user", pair[0]), avatarFilePrefix("user", pair[1])
		if strings.HasPrefix(b, a) || strings.HasPrefix(a, b) {
			t.Errorf("%q and %q share file names", pair[0], pair[1])
		}
	}
	if avatarFilePrefix("channel", "#Bash") != avatarFilePrefix("channel", "#bash") {
		t.Error("case variants of one channel get different files")
	}
}

func TestChannelRoutesTakeAnyChannelName(t *testing.T) {
	var got string
	capture := func(w http.ResponseWriter, r *http.Request) { got = mux.Vars(r)["channel"] }
	r := newRouter()
	r.HandleFunc("/upload/avatar/channel/{channel:.+}", capture)
	r.HandleFunc("/emoji/channel/{channel:.+}.json", capture)

	for _, name := range []string{"#a/b?c%d", "#a//b", "#a/../b"} {
		escaped := url.PathEscape(name)
		for _, path := range []string{
			"/upload/avatar/channel/" + escaped,
			"/emoji/channel/" + escaped + ".json",
		} {
			got = ""
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
			if rec.Code != http.StatusOK || got != name {
				t.Errorf("%s: status %d, channel %q, want %q", path, rec.Code, got, name)
			}
		}
	}
}

func TestStaticFilesStayInsideTheirFolderWithoutPathCleaning(t *testing.T) {
	root := t.TempDir()
	served := filepath.Join(root, "images")
	if err := os.Mkdir(served, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secret"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := newRouter()
	r.PathPrefix("/images/").Handler(http.StripPrefix("/images/", http.FileServer(http.Dir(served))))

	for _, path := range []string{"/images/../secret", "/images/%2e%2e/secret", "/images/..%2Fsecret"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if strings.Contains(rec.Body.String(), "secret") && rec.Code == http.StatusOK {
			t.Errorf("%s served a file outside the folder", path)
		}
	}
}

func TestChannelNamesFoldOnlyASCII(t *testing.T) {
	if ircFold("#FOO") != ircFold("#foo") {
		t.Error("ASCII case variants differ")
	}
	if ircFold("#Ä") == ircFold("#ä") || avatarFilePrefix("channel", "#Ä") == avatarFilePrefix("channel", "#ä") {
		t.Error("#Ä and #ä are distinct channels under CASEMAPPING=ascii")
	}
}

func TestChannelAvatarRefusesATokenForAnotherChannel(t *testing.T) {
	for _, pair := range [][2]string{{"#mine", "#other"}, {"#Ä", "#ä"}} {
		claims := authTokenToLegacyClaims(&AuthTokenClaims{
			Nick:       "alice",
			Account:    "alice",
			Scope:      "channel:" + pair[0],
			OperatorOf: pair[0],
		})
		req := httptest.NewRequest(http.MethodPost, "/upload/avatar/channel/"+url.PathEscape(pair[1]), nil)
		req = mux.SetURLVars(req, map[string]string{"channel": pair[1]})
		req = req.WithContext(context.WithValue(req.Context(), "jwt_claims", claims))
		rec := httptest.NewRecorder()

		uploadChannelAvatarHandler(rec, req, 1<<20, false, 0, 0, 0, false)

		if rec.Code != http.StatusForbidden {
			t.Errorf("token for %s on %s: status %d, want 403", pair[0], pair[1], rec.Code)
		}
	}
}

func TestDownloadRefusesInternalAddressesAndOtherSchemes(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secret"))
	}))
	defer internal.Close()

	for _, target := range []string{internal.URL, "file:///etc/passwd", "gopher://example.com/"} {
		if _, err := downloadPublicURL(target, 1<<20); err == nil {
			t.Errorf("downloaded %s", target)
		}
	}
}
