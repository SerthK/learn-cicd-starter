package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Empty Authorization Header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header - No Space",
			headers: http.Header{
				"Authorization": []string{"ApiKeysomekey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Incorrect Authorization Scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer somekey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Valid Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey somekey"},
			},
			expectedKey:   "somekey",
			expectedError: nil,
		},
		{
			name: "Authorization Header with Extra Parts",
			headers: http.Header{
				"Authorization": []string{"ApiKey somekey extra"},
			},
			expectedKey:   "somekey",
			expectedError: nil,
		},
		{
			name: "API Key is Empty String",
			headers: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			expectedKey:   "",
			expectedError: nil,
		},
		{
			name: "Authorization Header with Lowercase Scheme",
			headers: http.Header{
				"Authorization": []string{"apikey somekey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Authorization Header with Leading and Trailing Spaces",
			headers: http.Header{
				"Authorization": []string{"  ApiKey somekey  "},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)

			if apiKey != tt.expectedKey {
				t.Errorf("expected API key '%s', got '%s'", tt.expectedKey, apiKey)
			}

			if tt.expectedError != nil && err != nil {
				if err.Error() != tt.expectedError.Error() {
					t.Errorf("expected error '%v', got '%v'", tt.expectedError, err)
				}
			} else if tt.expectedError != err {
				t.Errorf("expected error '%v', got '%v'", tt.expectedError, err)
			}
		})
	}
}
