package def

import "net/http"

// LogoutHandler - GET /logout
func (e DefaultHandler) LogoutHandler(w http.ResponseWriter, _ *http.Request) {
	e.JWTService.Reset(w)
}
