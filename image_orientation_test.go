package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/jpeg"
	"testing"
	"time"
)

var (
	red   = color.RGBA{255, 0, 0, 255}
	green = color.RGBA{0, 255, 0, 255}
	blue  = color.RGBA{0, 0, 255, 255}
	white = color.RGBA{255, 255, 255, 255}
)

func quadrantJPEG(t *testing.T, orientation uint16) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 32, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 32; x++ {
			c := map[[2]bool]color.RGBA{
				{false, false}: red, {true, false}: green,
				{false, true}: blue, {true, true}: white,
			}[[2]bool{x >= 16, y >= 8}]
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 100}); err != nil {
		t.Fatal(err)
	}

	be := binary.BigEndian
	tiff := []byte("MM\x00\x2a\x00\x00\x00\x08")
	tiff = be.AppendUint16(tiff, 2)
	tiff = be.AppendUint16(tiff, 0x0112)
	tiff = be.AppendUint16(tiff, 3)
	tiff = be.AppendUint32(tiff, 1)
	tiff = be.AppendUint16(tiff, orientation)
	tiff = be.AppendUint16(tiff, 0)
	tiff = be.AppendUint16(tiff, 0x8825)
	tiff = be.AppendUint16(tiff, 4)
	tiff = be.AppendUint32(tiff, 1)
	tiff = be.AppendUint32(tiff, 38)
	tiff = be.AppendUint32(tiff, 0)
	tiff = be.AppendUint16(tiff, 1)
	tiff = be.AppendUint16(tiff, 0x0000)
	tiff = be.AppendUint16(tiff, 1)
	tiff = be.AppendUint32(tiff, 4)
	tiff = append(tiff, 2, 3, 0, 0)
	tiff = be.AppendUint32(tiff, 0)

	payload := append([]byte("Exif\x00\x00"), tiff...)
	app1 := be.AppendUint16([]byte{0xFF, 0xE1}, uint16(len(payload)+2))
	app1 = append(app1, payload...)

	encoded := buf.Bytes()
	out := append([]byte{}, encoded[:2]...)
	out = append(out, app1...)
	return append(out, encoded[2:]...)
}

func assertCorners(t *testing.T, img image.Image, want [4]color.RGBA) {
	t.Helper()
	b := img.Bounds()
	points := [4]image.Point{
		{b.Min.X + 2, b.Min.Y + 2}, {b.Max.X - 3, b.Min.Y + 2},
		{b.Min.X + 2, b.Max.Y - 3}, {b.Max.X - 3, b.Max.Y - 3},
	}
	for i, p := range points {
		r, g, bl, _ := img.At(p.X, p.Y).RGBA()
		got := [3]uint32{r >> 8, g >> 8, bl >> 8}
		exp := [3]uint32{uint32(want[i].R), uint32(want[i].G), uint32(want[i].B)}
		for c := range got {
			if diff := int(got[c]) - int(exp[c]); diff > 40 || diff < -40 {
				t.Errorf("corner %d at %v: got %v, want %v", i, p, got, exp)
				break
			}
		}
	}
}

func TestProcessImageAppliesExifOrientation(t *testing.T) {
	cases := []struct {
		name          string
		orientation   uint16
		width, height int
		corners       [4]color.RGBA
	}{
		{"rotate 90 cw", 6, 16, 32, [4]color.RGBA{blue, red, white, green}},
		{"rotate 180", 3, 32, 16, [4]color.RGBA{white, blue, green, red}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := quadrantJPEG(t, tc.orientation)
			if !bytes.Contains(in, []byte("Exif\x00\x00")) {
				t.Fatal("fixture has no EXIF block")
			}

			out, format, err := processImage(in, "nick:account", time.Now(), time.Now(), false, 1920, 1080, 95, false)
			if err != nil {
				t.Fatal(err)
			}
			if format != "jpeg" {
				t.Fatalf("format = %q, want jpeg", format)
			}
			if bytes.Contains(out, []byte("Exif\x00\x00")) || bytes.Contains(out, []byte{0xFF, 0xE1}) {
				t.Fatal("output still carries an EXIF block")
			}

			img, err := jpeg.Decode(bytes.NewReader(out))
			if err != nil {
				t.Fatal(err)
			}
			if b := img.Bounds(); b.Dx() != tc.width || b.Dy() != tc.height {
				t.Fatalf("size = %dx%d, want %dx%d", b.Dx(), b.Dy(), tc.width, tc.height)
			}
			assertCorners(t, img, tc.corners)
		})
	}
}
