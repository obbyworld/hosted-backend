package main

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestChannelAvatarRouteTakesAnyChannelName(t *testing.T) {
	var got string
	r := mux.NewRouter()
	r.HandleFunc("/upload/avatar/channel/{channel:.+}", func(w http.ResponseWriter, r *http.Request) {
		got = mux.Vars(r)["channel"]
	})
	req := httptest.NewRequest(http.MethodPost, "/upload/avatar/channel/%23a%2Fb%3Fc%25d", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)
	if got != "#a/b?c%d" {
		t.Fatalf("channel = %q, want #a/b?c%%d", got)
	}
}

func TestChannelAvatarRefusesATokenForAnotherChannel(t *testing.T) {
	claims := authTokenToLegacyClaims(&AuthTokenClaims{
		Nick:       "alice",
		Account:    "alice",
		Scope:      "channel:#mine",
		OperatorOf: "#mine",
	})
	req := httptest.NewRequest(http.MethodPost, "/upload/avatar/channel/%23other", nil)
	req = mux.SetURLVars(req, map[string]string{"channel": "#other"})
	req = req.WithContext(context.WithValue(req.Context(), "jwt_claims", claims))
	rec := httptest.NewRecorder()

	uploadChannelAvatarHandler(rec, req, 1<<20, false, 0, 0, 0, false)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
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
