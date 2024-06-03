package direct

import "github.com/gnaivex/auth/src/infrastructure/token"

// Handler implements non-oauth2 provider authorizing user in traditional way with storage
// with users and hashes
type Handler struct {
	UserIDFunc   UserIDFunc
	CredChecker  CredChecker
	ProviderName string
	Issuer       string

	JWTService token.Provider
}

// Name of the handler
func (p Handler) Name() string { return p.ProviderName }
