package token

import (
	"net/http"
	"time"
)

// Reset token's cookies
func (c *Client) Reset(w http.ResponseWriter) {
	jwtCookie := http.Cookie{Name: c.JWTCookieName, Value: "", HttpOnly: false, Path: "/", Domain: c.JWTCookieDomain,
		MaxAge: -1, Expires: time.Unix(0, 0), Secure: c.SecureCookies, SameSite: c.SameSite}
	http.SetCookie(w, &jwtCookie)

	xsrfCookie := http.Cookie{Name: c.XSRFCookieName, Value: "", HttpOnly: false, Path: "/", Domain: c.JWTCookieDomain,
		MaxAge: -1, Expires: time.Unix(0, 0), Secure: c.SecureCookies, SameSite: c.SameSite}
	http.SetCookie(w, &xsrfCookie)
}
