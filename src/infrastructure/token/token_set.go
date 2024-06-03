package token

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gnaivex/tools/jwt"
	jwtgo "github.com/golang-jwt/jwt"
)

func (c *Client) Set(w http.ResponseWriter, claims jwt.Claims) (jwt.Claims, error) {
	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = time.Now().Add(c.TokenDuration).Unix()
	}

	if claims.Issuer == "" {
		claims.Issuer = c.Issuer
	}

	if !c.DisableIAT {
		claims.IssuedAt = time.Now().Unix()
	}

	// Generating a new token
	// update claims with ClaimsUpdFunc defined by consumer
	if c.ClaimsUpd != nil {
		claims = c.ClaimsUpd.Update(claims)
	}

	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, claims)

	if c.SecretReader == nil {
		return jwt.Claims{}, fmt.Errorf("secret reader not defined")
	}

	if err := c.CheckAudience(&claims, c.AudienceReader); err != nil {
		return jwt.Claims{}, fmt.Errorf("aud rejected: %w", err)
	}

	secret, err := c.SecretReader.Get(claims.Audience) // get secret via consumer defined SecretReader
	if err != nil {
		return jwt.Claims{}, fmt.Errorf("can't get secret: %w", err)
	}

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return jwt.Claims{}, fmt.Errorf("can't sign token: %w", err)
	}

	if c.SendJWTHeader {
		w.Header().Set(c.JWTHeaderKey, tokenString)
		return claims, nil
	}

	cookieExpiration := 0 // session cookie
	if !claims.SessionOnly && claims.Handshake == nil {
		cookieExpiration = int(c.CookieDuration.Seconds())
	}

	jwtCookie := http.Cookie{
		Name:     c.JWTCookieName,
		Value:    tokenString,
		HttpOnly: true,
		Path:     "/",
		Domain:   c.JWTCookieDomain,
		MaxAge:   cookieExpiration,
		Secure:   c.SecureCookies,
		SameSite: c.SameSite,
	}

	http.SetCookie(w, &jwtCookie)

	xsrfCookie := http.Cookie{
		Name:     c.XSRFCookieName,
		Value:    claims.Id,
		HttpOnly: false,
		Path:     "/",
		Domain:   c.JWTCookieDomain,
		MaxAge:   cookieExpiration,
		Secure:   c.SecureCookies,
		SameSite: c.SameSite,
	}

	http.SetCookie(w, &xsrfCookie)

	return claims, nil
}
