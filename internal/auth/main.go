package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func MakeRefreshToken() (string, error) {
	var refreshToken []byte = make([]byte, 32)
	_, err := rand.Read(refreshToken)
	if err != nil {
		return "", fmt.Errorf("failed to generate refresh token: %v", err)
	}
	return hex.EncodeToString(refreshToken), nil
}

func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("http 'Authorization' header is not set")
	}

	if !strings.HasPrefix(authHeader, "ApiKey ") {
		return "", fmt.Errorf("http 'Authorization' header doesn't contain 'ApiKey' or malformed.")
	}

	apiKey := strings.Split(authHeader, " ")[1]
	if apiKey == "" {
		return "", fmt.Errorf("http 'Authorization' header doesn't contain 'ApiKey' or malformed.")
	}

	return apiKey, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("http 'Authorization' header is not set")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("http 'Authorization' header doesn't contain 'Bearer Token' or malformed.")
	}

	tokenString := strings.Split(authHeader, " ")[1]
	if tokenString == "" {
		return "", fmt.Errorf("http 'Authorization' header doesn't contain 'Bearer Token' or malformed.")
	}

	return tokenString, nil
}

func MakeJWT(userID uuid.UUID, tokenSecret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)),
		Subject:   userID.String(),
	})
	return token.SignedString([]byte(tokenSecret))
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Signing method did not match HMAC.")
		}
		return []byte(tokenSecret), nil
	})

	if err != nil {
		return uuid.Nil, fmt.Errorf("Failed to parse JWT token, error: %v", err)
	}

	uidString, err := token.Claims.GetSubject()
	if err != nil {
		return uuid.Nil, fmt.Errorf("Failed to parse 'Subject' from JWT token, error: %v", err)
	}

	return uuid.Parse(uidString)
}

func HashPassword(password string) (string, error) {
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return "", err
	}
	return hash, nil
}

func CheckPasswordHash(password, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(password, hash)
}
