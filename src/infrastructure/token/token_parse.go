package token

import (
	"fmt"

	"github.com/gnaivex/tools/jwt"
	jwtgo "github.com/golang-jwt/jwt"
)

func (c *Client) ParseToken(tokenString string) (jwt.Claims, error) {
	parser := jwtgo.Parser{SkipClaimsValidation: true} // allow parsing of expired tokens

	if c.SecretReader == nil {
		return jwt.Claims{}, fmt.Errorf("secret reader not defined")
	}

	aud := "ignore"
	if c.AudSecrets {
		var err error

		aud, err = c.FetchAudience(tokenString)
		if err != nil {
			return jwt.Claims{}, fmt.Errorf("can't retrieve audience from the token")
		}
	}

	secret, err := c.SecretReader.Get(aud)
	if err != nil {
		return jwt.Claims{}, fmt.Errorf("can't get secret: %w", err)
	}

	token, err := parser.ParseWithClaims(tokenString, &jwt.Claims{}, func(token *jwtgo.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwtgo.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(secret), nil
	})
	if err != nil {
		return jwt.Claims{}, fmt.Errorf("can't parse token: %w", err)
	}

	claims, ok := token.Claims.(*jwt.Claims)
	if !ok {
		return jwt.Claims{}, fmt.Errorf("invalid token")
	}

	if err = c.CheckAudience(claims, c.AudienceReader); err != nil {
		return jwt.Claims{}, fmt.Errorf("aud rejected: %w", err)
	}

	return *claims, jwt.Validate(claims)
}
