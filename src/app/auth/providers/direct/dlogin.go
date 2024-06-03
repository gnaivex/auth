package direct

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"

	"github.com/gnaivex/auth/src/app/auth/providers"
	"github.com/gnaivex/tools/jwt"
	jwtgo "github.com/golang-jwt/jwt"
)

const (
	// MaxHTTPBodySize defines max http body size
	MaxHTTPBodySize = 1024 * 1024
)

// credentials holds user credentials
type credentials struct {
	User     string `json:"user"`
	Password string `json:"passwd"`
	Audience string `json:"aud"`
}

// LoginHandler checks "user" and "passwd" against data store and makes jwt if all passed.
//
// GET /something?user=name&passwd=xyz&aud=bar&sess=[0|1]
//
// POST /something?sess[0|1]
// Accepts application/x-www-form-urlencoded or application/json encoded requests.
//
// application/x-www-form-urlencoded body example:
// user=name&passwd=xyz&aud=bar
//
// application/json body example:
//
//	{
//	  "user": "name",
//	  "passwd": "xyz",
//	  "aud": "bar",
//	}
func (p Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	uCredentials, err := p.getCredentials(w, r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("failed to parse credentials"))

		return
	}

	sessOnly := r.URL.Query().Get("sess") == "1"
	if p.CredChecker == nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("no credential checker"))

		return
	}

	ok, err := p.CredChecker.Check(uCredentials.User, uCredentials.Password)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("failed to check user credentials"))

		return
	}

	if !ok {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("incorrect user or password"))

		return
	}

	userID := p.ProviderName + "_" + jwt.HashID(sha1.New(), uCredentials.User)
	if p.UserIDFunc != nil {
		userID = p.ProviderName + "_" + jwt.HashID(sha1.New(), p.UserIDFunc(uCredentials.User, r))
	}

	u := jwt.User{
		Name: uCredentials.User,
		ID:   userID,
	}

	cid, err := providers.GenerateRandomToken()
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("can't make token id"))

		return
	}

	claims := jwt.Claims{
		User: &u,
		StandardClaims: jwtgo.StandardClaims{
			Id:       cid,
			Issuer:   p.Issuer,
			Audience: uCredentials.Audience,
		},
		SessionOnly: sessOnly,
	}

	if _, err = p.JWTService.Set(w, claims); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("failed to set token"))

		return
	}

	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(true)

	if err = enc.Encode(claims.User); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// getCredentials extracts user and password from request
func (p Handler) getCredentials(w http.ResponseWriter, r *http.Request) (credentials, error) {
	// GET /something?user=name&passwd=xyz&aud=bar
	if r.Method == "GET" {
		return credentials{
			User:     r.URL.Query().Get("user"),
			Password: r.URL.Query().Get("passwd"),
			Audience: r.URL.Query().Get("aud"),
		}, nil
	}

	if r.Method != "POST" {
		return credentials{}, fmt.Errorf("method %s not supported", r.Method)
	}

	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, MaxHTTPBodySize)
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "" {
		mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			return credentials{}, err
		}
		contentType = mt
	}

	// POST with json body
	if contentType == "application/json" {
		var creds credentials
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			return credentials{}, fmt.Errorf("failed to parse request body: %w", err)
		}
		return creds, nil
	}

	// POST with form
	if err := r.ParseForm(); err != nil {
		return credentials{}, fmt.Errorf("failed to parse request: %w", err)
	}

	return credentials{
		User:     r.Form.Get("user"),
		Password: r.Form.Get("passwd"),
		Audience: r.Form.Get("aud"),
	}, nil
}
