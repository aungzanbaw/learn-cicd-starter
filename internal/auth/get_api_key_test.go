package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErr    error
		wantErrMsg string
	}{
		{
			name:    "missing header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			wantKey: "abc123",
			wantErr: nil,
		},
		{
			name: "wrong scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			wantKey:    "",
			wantErrMsg: "malformed authorization header",
		},
		{
			name: "missing key after ApiKey",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey:    "",
			wantErrMsg: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("got key %q, want %q", gotKey, tt.wantKey)
			}

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("got err %v, want %v", err, tt.wantErr)
				}
			} else if tt.wantErrMsg != "" {
				if err == nil || err.Error() != tt.wantErrMsg {
					t.Errorf("got err %v, want message %q", err, tt.wantErrMsg)
				}
			} else if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
