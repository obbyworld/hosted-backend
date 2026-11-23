package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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

func postUserAvatar(t *testing.T, body []byte, maxUploadSize int64) *httptest.ResponseRecorder {
	t.Helper()
	claims := authTokenToLegacyClaims(&AuthTokenClaims{Nick: "alice", Account: "alice"})
	req := httptest.NewRequest(http.MethodPost, "/upload/avatar/user", bytes.NewReader(body))
	req.Header.Set("Content-Type", "image/png")
	req = req.WithContext(context.WithValue(req.Context(), "jwt_claims", claims))
	rec := httptest.NewRecorder()
	uploadUserAvatarHandler(rec, req, maxUploadSize, false, 0, 0, 80, false)
	return rec
}

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func chdirWithImagesFolder(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("images", 0o755); err != nil {
		t.Fatal(err)
	}
}

func savedAvatars(t *testing.T) int {
	t.Helper()
	files, err := os.ReadDir("images")
	if err != nil {
		t.Fatal(err)
	}
	return len(files)
}

func TestUserAvatarSavesANormalImage(t *testing.T) {
	chdirWithImagesFolder(t)
	rec := postUserAvatar(t, encodePNG(t, image.NewRGBA(image.Rect(0, 0, 64, 64))), 1<<20)
	if rec.Code != http.StatusOK || savedAvatars(t) != 1 {
		t.Fatalf("status %d, %d files saved: %s", rec.Code, savedAvatars(t), rec.Body.String())
	}
}

func TestUserAvatarRefusesABodyOverTheLimit(t *testing.T) {
	chdirWithImagesFolder(t)
	noise := image.NewRGBA(image.Rect(0, 0, 800, 800))
	if _, err := rand.Read(noise.Pix); err != nil {
		t.Fatal(err)
	}
	body := encodePNG(t, noise)
	const maxUploadSize = 1 << 10
	if int64(len(body)) <= avatarBodyLimit(maxUploadSize) {
		t.Fatalf("test image is only %d bytes", len(body))
	}
	rec := postUserAvatar(t, body, maxUploadSize)
	if rec.Code == http.StatusOK || savedAvatars(t) != 0 {
		t.Fatalf("status %d, %d files saved for a %d byte body", rec.Code, savedAvatars(t), len(body))
	}
}

// pngDeclaring rewrites the IHDR chunk so a tiny PNG declares the given size.
func pngDeclaring(t *testing.T, img image.Image, width, height uint32) []byte {
	t.Helper()
	data := encodePNG(t, img)
	binary.BigEndian.PutUint32(data[16:20], width)
	binary.BigEndian.PutUint32(data[20:24], height)
	binary.BigEndian.PutUint32(data[29:33], crc32.ChecksumIEEE(data[12:29]))
	return data
}

func TestProcessImageRefusesHugeDimensionsBeforeDecoding(t *testing.T) {
	data := pngDeclaring(t, image.NewGray(image.Rect(0, 0, 1, 1)), 100000, 100000)

	_, _, err := processImage(data, "alice:alice", time.Now(), time.Now(), false, 0, 0, 80, false)
	if !errors.Is(err, errImageTooLarge) {
		t.Fatalf("err = %v, want errImageTooLarge", err)
	}

	chdirWithImagesFolder(t)
	if rec := postUserAvatar(t, data, 1<<20); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("avatar status %d, want 413", rec.Code)
	}
}

func TestProcessImageRefusesA16BitImageOverTheDecodeBudget(t *testing.T) {
	data := pngDeclaring(t, image.NewRGBA64(image.Rect(0, 0, 1, 1)), 14000, 14000)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _, err := processImage(data, "alice:alice", time.Now(), time.Now(), false, 0, 0, 80, false)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, errImageTooLarge) {
		t.Fatalf("err = %v, want errImageTooLarge", err)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Fatalf("allocated %d bytes", grew)
	}
}

func TestDecodeBudgetFitsA200MegapixelPhoneJPEG(t *testing.T) {
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 16, 16)), nil); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	sof := bytes.Index(data, []byte{0xFF, 0xC0})
	if sof < 0 {
		t.Fatal("no SOF0 marker")
	}
	// The SOF0 segment holds a 2 byte length and 1 byte precision before height and width.
	binary.BigEndian.PutUint16(data[sof+5:], 12240)
	binary.BigEndian.PutUint16(data[sof+7:], 16320)

	if err := checkDecodeBudget(data); err != nil {
		t.Fatalf("a 16320x12240 JPEG was refused: %v", err)
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
