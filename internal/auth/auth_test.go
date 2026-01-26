package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid password",
			password: "testpassword123",
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  false,
		},
		{
			name:     "long password",
			password: "this_is_a_very_long_password_with_many_characters_1234567890",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && hash == "" {
				t.Error("HashPassword() returned empty hash")
			}
			if !tt.wantErr && hash == tt.password {
				t.Error("HashPassword() returned plaintext password instead of hash")
			}
		})
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "testpassword123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password for test: %v", err)
	}

	tests := []struct {
		name      string
		password  string
		hash      string
		wantMatch bool
		wantErr   bool
	}{
		{
			name:      "correct password",
			password:  password,
			hash:      hash,
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "incorrect password",
			password:  "wrongpassword",
			hash:      hash,
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "empty password",
			password:  "",
			hash:      hash,
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "invalid hash format",
			password:  password,
			hash:      "not_a_valid_hash",
			wantMatch: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := CheckPasswordHash(tt.password, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if match != tt.wantMatch {
				t.Errorf("CheckPasswordHash() match = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

func TestHashPasswordConsistency(t *testing.T) {
	password := "testpassword"

	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	// Hashes should be different due to salt
	if hash1 == hash2 {
		t.Error("HashPassword() generated identical hashes, should use different salts")
	}

	// But both should validate correctly
	match1, err := CheckPasswordHash(password, hash1)
	if err != nil || !match1 {
		t.Errorf("First hash doesn't validate: match=%v, err=%v", match1, err)
	}

	match2, err := CheckPasswordHash(password, hash2)
	if err != nil || !match2 {
		t.Errorf("Second hash doesn't validate: match=%v, err=%v", match2, err)
	}
}

func TestMakeJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret-key"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}

	if token == "" {
		t.Error("MakeJWT() returned empty token")
	}

	// Token should be a JWT (has three parts separated by dots)
	parts := 0
	for _, c := range token {
		if c == '.' {
			parts++
		}
	}
	if parts != 2 {
		t.Errorf("MakeJWT() returned malformed token, expected 3 parts (2 dots), got %d dots", parts)
	}
}

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret-key"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	tests := []struct {
		name        string
		tokenString string
		tokenSecret string
		wantUserID  uuid.UUID
		wantErr     bool
	}{
		{
			name:        "valid token",
			tokenString: token,
			tokenSecret: tokenSecret,
			wantUserID:  userID,
			wantErr:     false,
		},
		{
			name:        "wrong secret",
			tokenString: token,
			tokenSecret: "wrong-secret",
			wantUserID:  uuid.Nil,
			wantErr:     true,
		},
		{
			name:        "malformed token",
			tokenString: "not.a.valid.jwt",
			tokenSecret: tokenSecret,
			wantUserID:  uuid.Nil,
			wantErr:     true,
		},
		{
			name:        "empty token",
			tokenString: "",
			tokenSecret: tokenSecret,
			wantUserID:  uuid.Nil,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserID, err := ValidateJWT(tt.tokenString, tt.tokenSecret)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotUserID != tt.wantUserID {
				t.Errorf("ValidateJWT() userID = %v, want %v", gotUserID, tt.wantUserID)
			}
		})
	}
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret-key"
	expiresIn := -time.Hour // Already expired

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	_, err = ValidateJWT(token, tokenSecret)
	if err == nil {
		t.Error("ValidateJWT() should reject expired token")
	}
}

func TestJWT_RoundTrip(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret-key-12345"
	expiresIn := time.Hour * 24

	// Create token
	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT() failed: %v", err)
	}

	// Validate token
	retrievedUserID, err := ValidateJWT(token, tokenSecret)
	if err != nil {
		t.Fatalf("ValidateJWT() failed: %v", err)
	}

	// Should get back the same user ID
	if retrievedUserID != userID {
		t.Errorf("Round trip failed: got userID %v, want %v", retrievedUserID, userID)
	}
}

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name      string
		authValue string
		wantToken string
		wantErr   bool
	}{
		{
			name:      "valid bearer token",
			authValue: "Bearer my-token-123",
			wantToken: "my-token-123",
			wantErr:   false,
		},
		{
			name:      "valid bearer with JWT",
			authValue: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			wantToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			wantErr:   false,
		},
		{
			name:      "missing Bearer prefix",
			authValue: "my-token-123",
			wantToken: "",
			wantErr:   true,
		},
		{
			name:      "wrong prefix",
			authValue: "Basic my-token-123",
			wantToken: "",
			wantErr:   true,
		},
		{
			name:      "empty header",
			authValue: "",
			wantToken: "",
			wantErr:   true,
		},
		{
			name:      "Bearer with no token",
			authValue: "Bearer",
			wantToken: "",
			wantErr:   true,
		},
		{
			name:      "extra spaces",
			authValue: "Bearer  my-token-123",
			wantToken: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authValue != "" {
				headers.Set("Authorization", tt.authValue)
			}

			token, err := GetBearerToken(headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetBearerToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if token != tt.wantToken {
				t.Errorf("GetBearerToken() token = %v, want %v", token, tt.wantToken)
			}
		})
	}
}
