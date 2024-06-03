package token

import (
	"fmt"
	"strings"

	"github.com/gnaivex/tools/jwt"
)

// CheckAudience verifies if audience in the list of allowed by audReader
func (c *Client) CheckAudience(claims *jwt.Claims, audReader jwt.Audience) error {
	if audReader == nil { // lack of any allowed means any
		return nil
	}

	audiences, err := audReader.Get()
	if err != nil {
		return fmt.Errorf("failed to get auds: %w", err)
	}

	for _, a := range audiences {
		if strings.EqualFold(a, claims.Audience) {
			return nil
		}
	}

	return fmt.Errorf("aud %q not allowed", claims.Audience)
}
