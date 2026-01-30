package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

const tokenSecret = "db27a3ff44e6b0f107a66a7c552a72b3"

// validate bearer token
func TestHttpBearerToken(t *testing.T) {
	header := http.Header{}
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJjaGlycHkiLCJzdWIiOiJhYTBhZDZiYi03ZjFhLTRmNzEtYTYyOS1iOTAzZTFkZTI4MDkiLCJleHAiOjE3Njk4MDI0NTMsImlhdCI6MTc2OTgwMjMzM30.12QnUrfJoCHXIDj_EEdT8zFCPpEHQgkXwndBF063zi4"
	header.Set("Authorization", "Bearer "+token)
	retToken, err := GetBearerToken(header)
	if err != nil {
		t.Errorf("Failed to parse GetBearerToken, err: %v", err)
	}
	if retToken != token {
		t.Errorf("Retrieved bearer token is not matching. Retrieved token: %s", retToken)
	}
	t.Logf("Retrieved token: %s", retToken)
}

// Test Create & Validate JWT token
func TestJWTValidation(t *testing.T) {
	jwtToken, err := MakeJWT(uuid.New(), tokenSecret, time.Duration(time.Second*120))
	if err != nil {
		t.Errorf("Failed to get JWT token from auth module. Err: %v", err)
	}
	t.Logf("Recieved JWT Token: %s", jwtToken)

	userId, err := ValidateJWT(jwtToken, tokenSecret)
	if err != nil {
		t.Errorf("JWT token validation failed. Err msg: %v", err)
	}
	t.Logf("JWT token validated succesfully. User Id: %s", userId)
}

// Validate expired tokens
func TestExpiredToken(t *testing.T) {
	jwtToken, err := MakeJWT(uuid.New(), tokenSecret, time.Duration(time.Second*5))
	if err != nil {
		t.Errorf("Failed to get JWT token from auth module. Err: %v", err)
	}
	t.Logf("Recieved JWT Token: %s", jwtToken)
	t.Logf("Sleeping for 10s to expire JWT token")
	time.Sleep(time.Duration(time.Second * 10))

	_, err = ValidateJWT(jwtToken, tokenSecret)
	if err == nil {
		t.Error("Validate JWT works with wrong secret too")
	}
	t.Logf("JWT token validation failed as expected. Err msg: %v", err)
}

// validate JWT signed with wrong tokens
func TestWrongSecretToken(t *testing.T) {
	dummyToken := "a489325ab583fdaa5266d7dd7b0c6923"
	userId := uuid.New()
	jwtToken, err := MakeJWT(userId, tokenSecret, time.Duration(time.Second*120))
	if err != nil {
		t.Errorf("Failed to get JWT token from auth module. Err: %v", err)
	}
	t.Logf("Recieved JWT Token: %s", jwtToken)

	_, err = ValidateJWT(jwtToken, dummyToken)
	if err == nil {
		t.Error("Validate JWT works with wrong secret too")
	}
	t.Logf("JWT token validation failed as expected. Err msg: %v", err)
}
