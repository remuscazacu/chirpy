package auth

import (
	"testing"
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
