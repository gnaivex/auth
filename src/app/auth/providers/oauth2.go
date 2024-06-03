package providers

import (
	"golang.org/x/oauth2"

	"github.com/gnaivex/auth/src/infrastructure/token"
	"github.com/gnaivex/tools/jwt"
)

// Oauth2Handler implements /login, /callback and /logout handlers from oauth2 flow
type Oauth2Handler struct {
	Params

	// all of these fields specific to particular oauth2 provider
	name            string
	infoURL         string
	endpoint        oauth2.Endpoint
	scopes          []string
	mapUser         func(UserData, []byte) jwt.User // map info from InfoURL to User
	bearerTokenHook BearerTokenHook                 // a way to get a Bearer token received from oauth2-provider
	conf            oauth2.Config
}

// Params to make initialized and ready to use provider
type Params struct {
	URL            string
	JWTService     token.Provider
	CID            string
	CSecret        string
	Issuer         string
	UserAttributes UserAttributes
}

// UserAttributes is the type that will be used to map user data from provider to token.User
type UserAttributes map[string]string

// UserData is type for user information returned from oauth2 providers /info API method
type UserData map[string]interface{}

// BearerTokenHook accepts provider name, user and token, received during oauth2 authentication
type BearerTokenHook func(provider string, user jwt.User, token oauth2.Token)
