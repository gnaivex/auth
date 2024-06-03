package token

import (
	"time"

	"github.com/gnaivex/tools/jwt"
)

// IsExpired returns true if claims expired
func (c *Client) IsExpired(claims jwt.Claims) bool {
	return !claims.VerifyExpiresAt(time.Now().Unix(), true)
}
