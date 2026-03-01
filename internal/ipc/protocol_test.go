package ipc

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		tag     byte
		payload []byte
	}{
		{"request tag", TagRequest, []byte(`{"args":["echo","hello"]}`)},
		{"stdin data", TagStdinData, []byte("hello world")},
		{"stdin eof", TagStdinEOF, nil},
		{"signal", TagSignal, []byte(`{"signal":"INT"}`)},
		{"stdout data", TagStdoutData, []byte("output here")},
		{"stderr data", TagStderrData, []byte("error here")},
		{"exit", TagExit, []byte(`{"code":0}`)},
		{"empty payload", TagStdoutData, []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteFrame(&buf, tt.tag, tt.payload); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}

			gotTag, gotPayload, err := ReadFrame(&buf)
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if gotTag != tt.tag {
				t.Errorf("tag = 0x%02x, want 0x%02x", gotTag, tt.tag)
			}
			if !bytes.Equal(gotPayload, tt.payload) {
				t.Errorf("payload = %q, want %q", gotPayload, tt.payload)
			}
		})
	}
}

func TestWriteJSONRoundTrip(t *testing.T) {
	t.Run("request", func(t *testing.T) {
		req := Request{
			Args:  []string{"grep", "foo"},
			Cwd:   "/tmp",
			Retry: true,
			Env:   map[string]string{"HOME": "/home/test"},
		}
		var buf bytes.Buffer
		if err := WriteJSON(&buf, TagRequest, req); err != nil {
			t.Fatalf("WriteJSON: %v", err)
		}

		tag, payload, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if tag != TagRequest {
			t.Errorf("tag = 0x%02x, want 0x%02x", tag, TagRequest)
		}

		var got Request
		if err := json.Unmarshal(payload, &got); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if len(got.Args) != 2 || got.Args[0] != "grep" || got.Args[1] != "foo" {
			t.Errorf("args = %v, want [grep foo]", got.Args)
		}
		if got.Cwd != "/tmp" {
			t.Errorf("cwd = %q, want /tmp", got.Cwd)
		}
		if !got.Retry {
			t.Error("retry = false, want true")
		}
		if got.Env["HOME"] != "/home/test" {
			t.Errorf("env HOME = %q, want /home/test", got.Env["HOME"])
		}
	})

	t.Run("exit result", func(t *testing.T) {
		res := ExitResult{Code: 1, Error: "command failed"}
		var buf bytes.Buffer
		if err := WriteJSON(&buf, TagExit, res); err != nil {
			t.Fatalf("WriteJSON: %v", err)
		}

		tag, payload, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if tag != TagExit {
			t.Errorf("tag = 0x%02x, want 0x%02x", tag, TagExit)
		}

		var got ExitResult
		if err := json.Unmarshal(payload, &got); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if got.Code != 1 {
			t.Errorf("code = %d, want 1", got.Code)
		}
		if got.Error != "command failed" {
			t.Errorf("error = %q, want %q", got.Error, "command failed")
		}
	})

	t.Run("signal", func(t *testing.T) {
		sig := SignalMsg{Signal: "INT"}
		var buf bytes.Buffer
		if err := WriteJSON(&buf, TagSignal, sig); err != nil {
			t.Fatalf("WriteJSON: %v", err)
		}

		tag, payload, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if tag != TagSignal {
			t.Errorf("tag = 0x%02x, want 0x%02x", tag, TagSignal)
		}

		var got SignalMsg
		if err := json.Unmarshal(payload, &got); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if got.Signal != "INT" {
			t.Errorf("signal = %q, want INT", got.Signal)
		}
	})
}

func TestSequentialFrames(t *testing.T) {
	var buf bytes.Buffer

	frames := []struct {
		tag     byte
		payload []byte
	}{
		{TagStdoutData, []byte("line 1\n")},
		{TagStderrData, []byte("warning\n")},
		{TagStdoutData, []byte("line 2\n")},
		{TagExit, []byte(`{"code":0}`)},
	}

	for _, f := range frames {
		if err := WriteFrame(&buf, f.tag, f.payload); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
	}

	for i, want := range frames {
		tag, payload, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("frame %d: ReadFrame: %v", i, err)
		}
		if tag != want.tag {
			t.Errorf("frame %d: tag = 0x%02x, want 0x%02x", i, tag, want.tag)
		}
		if !bytes.Equal(payload, want.payload) {
			t.Errorf("frame %d: payload = %q, want %q", i, payload, want.payload)
		}
	}

	// No more frames.
	_, _, err := ReadFrame(&buf)
	if err == nil {
		t.Error("expected error reading past end, got nil")
	}
}

func TestLargePayload(t *testing.T) {
	payload := []byte(strings.Repeat("x", 1<<20)) // 1 MB
	var buf bytes.Buffer
	if err := WriteFrame(&buf, TagStdoutData, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	tag, got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if tag != TagStdoutData {
		t.Errorf("tag = 0x%02x, want 0x%02x", tag, TagStdoutData)
	}
	if len(got) != len(payload) {
		t.Errorf("payload length = %d, want %d", len(got), len(payload))
	}
}

func TestReadFrameTruncatedHeader(t *testing.T) {
	// Only 3 bytes — header needs 5.
	r := bytes.NewReader([]byte{0x01, 0x00, 0x00})
	_, _, err := ReadFrame(r)
	if err == nil {
		t.Error("expected error for truncated header, got nil")
	}
}

func TestReadFrameTruncatedPayload(t *testing.T) {
	// Header says 10 bytes of payload but only 3 are present.
	var buf bytes.Buffer
	buf.Write([]byte{TagStdoutData, 0x00, 0x00, 0x00, 0x0a}) // length = 10
	buf.Write([]byte("abc"))                                    // only 3 bytes

	_, _, err := ReadFrame(&buf)
	if err == nil {
		t.Error("expected error for truncated payload, got nil")
	}
}

func TestReadFrameEmptyReader(t *testing.T) {
	_, _, err := ReadFrame(bytes.NewReader(nil))
	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
}
