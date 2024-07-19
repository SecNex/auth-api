package auth

import (
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"

	"github.com/google/uuid"
)

type AuthenticationHeader struct {
	Type  string
	Value string
	Token string
}

type Authentication struct {
	ID        uuid.UUID
	Header    AuthenticationHeader
	ExpiresIn int
}

func newRandomString(length int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func stringToBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func NewUUID() uuid.UUID {
	return uuid.New()
}

func NewAuthentication() *Authentication {
	return &Authentication{
		ID:        uuid.New(),
		ExpiresIn: 3600,
	}
}

func NewAuthenticationWithID(id uuid.UUID) *Authentication {
	return &Authentication{
		ID:        id,
		ExpiresIn: 3600,
	}
}

func (a *Authentication) GenerateToken() string {
	log.Printf("Generating token for authentication: %v", a.ID)
	value := newRandomString(32)
	token := fmt.Sprintf("%v:%v", a.ID, value)
	log.Printf("Generated token: %v", token)
	a.Header = AuthenticationHeader{
		Type:  "Bearer",
		Value: value,
		Token: stringToBase64(token),
	}
	return a.Header.Token
}

func (a *Authentication) GenerateTokenWithSecret(secret string) string {
	log.Printf("Generating token for authentication: %v", a.ID)
	token := fmt.Sprintf("%v:%v", a.ID, secret)
	log.Printf("Generated token: %v", token)
	a.Header = AuthenticationHeader{
		Type:  "Bearer",
		Value: secret,
		Token: stringToBase64(token),
	}
	return a.Header.Token
}

func GenerateRandomString(length int) string {
	return newRandomString(length)
}
