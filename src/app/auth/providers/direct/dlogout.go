package direct

import "net/http"

// LogoutHandler - GET /logout
func (p Handler) LogoutHandler(w http.ResponseWriter, _ *http.Request) {
	p.JWTService.Reset(w)
}
