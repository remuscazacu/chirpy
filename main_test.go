package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCleanProfaneWords(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no profane words",
			input: "This is a clean message",
			want:  "This is a clean message",
		},
		{
			name:  "single profane word",
			input: "This is kerfuffle",
			want:  "This is ****",
		},
		{
			name:  "multiple profane words",
			input: "What a kerfuffle with sharbert",
			want:  "What a **** with ****",
		},
		{
			name:  "profane word in different case",
			input: "What a KERFUFFLE and Sharbert",
			want:  "What a **** and ****",
		},
		{
			name:  "all profane words",
			input: "kerfuffle sharbert fornax",
			want:  "**** **** ****",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "profane word as part of larger word should not match",
			input: "kerfuffles",
			want:  "kerfuffles",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanProfaneWords(tt.input)
			if got != tt.want {
				t.Errorf("cleanProfaneWords() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRespondWithJSON(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		payload    interface{}
		wantBody   string
	}{
		{
			name:       "success with struct",
			statusCode: http.StatusOK,
			payload:    struct{ Message string }{Message: "test"},
			wantBody:   `{"Message":"test"}`,
		},
		{
			name:       "error status",
			statusCode: http.StatusBadRequest,
			payload:    map[string]string{"error": "bad request"},
			wantBody:   `{"error":"bad request"}`,
		},
		{
			name:       "empty object",
			statusCode: http.StatusOK,
			payload:    struct{}{},
			wantBody:   `{}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			respondWithJSON(w, tt.statusCode, tt.payload)

			if w.Code != tt.statusCode {
				t.Errorf("respondWithJSON() status = %v, want %v", w.Code, tt.statusCode)
			}

			if contentType := w.Header().Get("Content-Type"); contentType != "application/json" {
				t.Errorf("respondWithJSON() Content-Type = %v, want application/json", contentType)
			}

			if w.Body.String() != tt.wantBody {
				t.Errorf("respondWithJSON() body = %v, want %v", w.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestRespondWithError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		message    string
	}{
		{
			name:       "bad request",
			statusCode: http.StatusBadRequest,
			message:    "Invalid request",
		},
		{
			name:       "unauthorized",
			statusCode: http.StatusUnauthorized,
			message:    "Unauthorized",
		},
		{
			name:       "internal server error",
			statusCode: http.StatusInternalServerError,
			message:    "Internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			respondWithError(w, tt.statusCode, tt.message)

			if w.Code != tt.statusCode {
				t.Errorf("respondWithError() status = %v, want %v", w.Code, tt.statusCode)
			}

			if contentType := w.Header().Get("Content-Type"); contentType != "application/json" {
				t.Errorf("respondWithError() Content-Type = %v, want application/json", contentType)
			}

			var response struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			if response.Error != tt.message {
				t.Errorf("respondWithError() error message = %v, want %v", response.Error, tt.message)
			}
		})
	}
}

func TestHandlerReadiness(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/healthz", nil)
	w := httptest.NewRecorder()

	handlerReadiness(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("handlerReadiness() status = %v, want %v", w.Code, http.StatusOK)
	}

	if contentType := w.Header().Get("Content-Type"); contentType != "text/plain; charset=utf-8" {
		t.Errorf("handlerReadiness() Content-Type = %v, want text/plain; charset=utf-8", contentType)
	}

	if w.Body.String() != "OK" {
		t.Errorf("handlerReadiness() body = %v, want OK", w.Body.String())
	}
}

func TestHandlerCreateChirp_InvalidJSON(t *testing.T) {
	cfg := &apiConfig{}
	req := httptest.NewRequest(http.MethodPost, "/api/chirps", nil)
	w := httptest.NewRecorder()

	cfg.handlerCreateChirp(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("handlerCreateChirp() with no body status = %v, want %v", w.Code, http.StatusBadRequest)
	}

	var response struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response.Error != "Invalid request" {
		t.Errorf("handlerCreateChirp() error = %v, want Invalid request", response.Error)
	}
}

func TestHandlerCreateUser_InvalidJSON(t *testing.T) {
	cfg := &apiConfig{}
	req := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	w := httptest.NewRecorder()

	cfg.handlerCreateUser(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("handlerCreateUser() with no body status = %v, want %v", w.Code, http.StatusBadRequest)
	}

	var response struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response.Error != "Invalid request" {
		t.Errorf("handlerCreateUser() error = %v, want Invalid request", response.Error)
	}
}

func TestHandlerLogin_InvalidJSON(t *testing.T) {
	cfg := &apiConfig{}
	req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	w := httptest.NewRecorder()

	cfg.handlerLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("handlerLogin() with no body status = %v, want %v", w.Code, http.StatusBadRequest)
	}

	var response struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response.Error != "Invalid request" {
		t.Errorf("handlerLogin() error = %v, want Invalid request", response.Error)
	}
}
