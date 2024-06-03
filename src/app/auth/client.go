package auth

import "net/http"

// Provider defines interface for auth handler
type Provider interface {
	Name() string
	LoginHandler(w http.ResponseWriter, r *http.Request)
	AuthHandler(w http.ResponseWriter, r *http.Request)
	LogoutHandler(w http.ResponseWriter, r *http.Request)
}

type Authenticator interface {
	Auth(next http.Handler) http.Handler
}

// Service represents oauth2 provider. Adds Handler method multiplexing login, auth and logout requests
type Service struct {
	Provider
}

// NewClient makes service for given provider
func NewClient(p Provider) Service {
	return Service{Provider: p}
}
