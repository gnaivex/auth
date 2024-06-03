package token

import (
	"fmt"
	"strings"

	"github.com/gnaivex/tools/jwt"
	jwtgo "github.com/golang-jwt/jwt"
)

func (c *Client) FetchAudience(tokenString string) (string, error) {
	parser := jwtgo.Parser{}

	token, _, err := parser.ParseUnverified(tokenString, &jwt.Claims{})
	if err != nil {
		return "", fmt.Errorf("can't pre-parse token: %w", err)
	}

	claims, ok := token.Claims.(*jwt.Claims)
	if !ok {
		return "", fmt.Errorf("invalid token")
	}

	if strings.TrimSpace(claims.Audience) == "" {
		return "", fmt.Errorf("empty aud")
	}

	return claims.Audience, nil
}
