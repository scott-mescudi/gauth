package errors

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestErrorWithJson(t *testing.T) {
	tests := []struct {
		code     int
		message  string
		expected string
	}{
		{http.StatusBadRequest, "Bad Request", `{"error":"Bad Request","code":400}`},
		{http.StatusUnauthorized, "Unauthorized", `{"error":"Unauthorized","code":401}`},
		{http.StatusNotFound, "Not Found", `{"error":"Not Found","code":404}`},
	}

	for _, test := range tests {
		t.Run(test.message, func(t *testing.T) {
			rr := httptest.NewRecorder()

			ErrorWithJson(rr, test.code, test.message)

			res := rr.Result()
			defer res.Body.Close()

			if res.StatusCode != test.code {
				t.Errorf("expected status %d, got %d", test.code, res.StatusCode)
			}

			var response map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
				t.Errorf("failed to decode response: %v", err)
			}

			if response["error"] != test.message {
				t.Errorf("expected error message %s, got %s", test.message, response["error"])
			}

			if response["code"] != float64(test.code) {
				t.Errorf("expected code %d, got %v", test.code, response["code"])
			}
		})
	}
}
