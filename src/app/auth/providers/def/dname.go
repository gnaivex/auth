package def

import "github.com/gnaivex/auth/src/infrastructure/token"

// DefaultHandler implements non-oauth2 provider authorizing users with some confirmation.
// can be email or anything else implementing Sender interface
type DefaultHandler struct {
	ProviderName string
	Issuer       string
	Template     string

	Sender     Sender
	JWTService token.Provider
}

// Name of the handler
func (e DefaultHandler) Name() string { return e.ProviderName }
