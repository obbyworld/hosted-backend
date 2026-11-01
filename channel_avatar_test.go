package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func TestChannelAvatarPrefixKeepsSlashesOutOfTheFileName(t *testing.T) {
	prefix := channelAvatarPrefix("#!/bin/bash")
	if strings.ContainsAny(prefix, "/\\.") {
		t.Fatalf("prefix %q can leave the images folder", prefix)
	}
	if channelAvatarPrefix("#a/b") == channelAvatarPrefix("#a_b") {
		t.Fatal("two channels share one prefix")
	}
	if channelAvatarPrefix("#Bash") != channelAvatarPrefix("#bash") {
		t.Fatal("case variants of one channel get different prefixes")
	}
}

func TestChannelRouteMatchesNamesWithSlashes(t *testing.T) {
	var got string
	r := mux.NewRouter()
	r.HandleFunc("/upload/avatar/channel/{channel:.+}", func(w http.ResponseWriter, r *http.Request) {
		got = mux.Vars(r)["channel"]
	})
	req := httptest.NewRequest(http.MethodPost, "/upload/avatar/channel/%23!%2Fbin%2Fbash", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)
	if got != "#!/bin/bash" {
		t.Fatalf("channel = %q, want #!/bin/bash", got)
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
