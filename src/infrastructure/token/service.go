package token

import (
	"net/http"
	"time"

	"github.com/gnaivex/tools/jwt"
)

// Default constants - write options to add possibility to overwrite them
const (
	defaultJWTCookieName   = "JWT"
	defaultJWTCookieDomain = ""
	defaultJWTHeaderKey    = "X-JWT"
	defaultXSRFCookieName  = "XSRF-TOKEN"
	defaultXSRFHeaderKey   = "X-XSRF-TOKEN"
	defaultIssuer          = "go-pkgz/auth"
	defaultTokenDuration   = time.Minute * 15
	defaultCookieDuration  = time.Hour * 24 * 31
	defaultTokenQuery      = "token"
)

type Provider interface {
	GenerateToken(claims jwt.Claims) (string, error)
	ParseToken(tokenString string) (jwt.Claims, error)
	Set(w http.ResponseWriter, claims jwt.Claims) (jwt.Claims, error)
	Get(r *http.Request) (claims jwt.Claims, token string, err error)
	IsExpired(claims jwt.Claims) bool
	Reset(w http.ResponseWriter)
}

type Client struct {
	SecretReader    jwt.Secret        // Reads secret from token
	ClaimsUpd       jwt.ClaimsUpdater // Update claims
	SecureCookies   bool
	TokenDuration   time.Duration
	CookieDuration  time.Duration
	DisableXSRF     bool
	DisableIAT      bool
	JWTCookieName   string
	JWTCookieDomain string
	JWTHeaderKey    string
	XSRFCookieName  string
	XSRFHeaderKey   string
	JWTQuery        string
	AudienceReader  jwt.Audience  // allowed aud values
	Issuer          string        // optional value for iss claim, usually application name
	AudSecrets      bool          // uses different secret for differed auds. important: adds pre-parsing of unverified token
	SendJWTHeader   bool          // if enabled send JWT as a header instead of cookie
	SameSite        http.SameSite // define a cookie attribute making it impossible for the browser to send this cookie cross-site
}

func New(scr jwt.Secret, clm jwt.ClaimsUpdater, aud jwt.Audience) *Client {
	svc := Client{
		SecretReader:    scr,
		ClaimsUpd:       clm,
		SecureCookies:   false,
		TokenDuration:   defaultTokenDuration,
		CookieDuration:  defaultCookieDuration,
		DisableXSRF:     false,
		DisableIAT:      false,
		JWTCookieName:   defaultJWTCookieName,
		JWTCookieDomain: defaultJWTCookieDomain,
		JWTHeaderKey:    defaultJWTHeaderKey,
		XSRFCookieName:  defaultXSRFCookieName,
		XSRFHeaderKey:   defaultXSRFHeaderKey,
		JWTQuery:        defaultTokenQuery,
		AudienceReader:  aud,
		Issuer:          defaultIssuer,
		AudSecrets:      false,
		SendJWTHeader:   false,
		SameSite:        0,
	}

	return &svc
}
