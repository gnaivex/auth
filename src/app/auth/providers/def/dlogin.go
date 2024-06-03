package def

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/gnaivex/auth/src/app/auth/providers"
	"github.com/gnaivex/tools/jwt"
	jwtgo "github.com/golang-jwt/jwt"
)

// LoginHandler gets name and address from query, makes confirmation token and sends it to user.
// In case if confirmation token presented in the query uses it to create auth token
func (e DefaultHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// GET /login?site=site&user=name&address=someone@example.com
	tkn := r.URL.Query().Get("token")
	if tkn == "" { // no token, ask confirmation via email
		e.sendConfirmation(w, r)

		return
	}

	// confirmation token presented
	// GET /login?token=confirmation-jwt&sess=1
	confClaims, err := e.JWTService.ParseToken(tkn)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("failed to verify confirmation token"))

		return
	}

	if e.JWTService.IsExpired(confClaims) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("failed to verify confirmation token"))

		return
	}

	elems := strings.Split(confClaims.Handshake.ID, "::")
	if len(elems) != 2 {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid handshake token"))

		return
	}

	user, address := elems[0], elems[1]
	sessOnly := r.URL.Query().Get("sess") == "1"

	u := jwt.User{
		Name: user,
		ID:   e.ProviderName + "_" + jwt.HashID(sha1.New(), address),
	}

	cid, err := providers.GenerateRandomToken()
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("can't make token id"))

		return
	}

	claims := jwt.Claims{
		User: &u,
		StandardClaims: jwtgo.StandardClaims{
			Id:       cid,
			Issuer:   e.Issuer,
			Audience: confClaims.Audience,
		},
		SessionOnly: sessOnly,
	}

	if _, err = e.JWTService.Set(w, claims); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("failed to set token"))

		return
	}

	if confClaims.Handshake != nil && confClaims.Handshake.From != "" {
		http.Redirect(w, r, confClaims.Handshake.From, http.StatusTemporaryRedirect)

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

// GET /login?site=site&user=name&address=someone@example.com
func (e DefaultHandler) sendConfirmation(w http.ResponseWriter, r *http.Request) {
	user, address, site := r.URL.Query().Get("user"), r.URL.Query().Get("address"), r.URL.Query().Get("site")

	if user == "" || address == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("can't get user and address"))

		return
	}

	claims := jwt.Claims{
		Handshake: &jwt.Handshake{
			State: "",
			ID:    user + "::" + address,
		},
		SessionOnly: r.URL.Query().Get("session") != "" && r.URL.Query().Get("session") != "0",
		StandardClaims: jwtgo.StandardClaims{
			Audience:  site,
			ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
			NotBefore: time.Now().Add(-1 * time.Minute).Unix(),
			Issuer:    e.Issuer,
		},
	}

	tkn, err := e.JWTService.GenerateToken(claims)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("failed to make login token"))

		return
	}

	tmpl := msgTemplate
	if e.Template != "" {
		tmpl = e.Template
	}

	emailTmpl, err := template.New("confirm").Parse(tmpl)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("can't parse confirmation template"))

		return
	}

	tmplData := struct {
		User    string
		Address string
		Token   string
		Site    string
	}{
		User:    trim(user),
		Address: trim(address),
		Token:   tkn,
		Site:    site,
	}
	buf := bytes.Buffer{}
	if err = emailTmpl.Execute(&buf, tmplData); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("can't execute confirmation template"))

		return
	}

	if err = e.Sender.Send(address, buf.String()); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("failed to send confirmation"))

		return
	}

	buf = bytes.Buffer{}
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(true)

	s := struct {
		User    string `json:"user"`
		Address string `json:"address"`
	}{
		User:    user,
		Address: address,
	}

	if err = enc.Encode(s); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

var msgTemplate = `
Confirmation for {{.User}} {{.Address}}, site {{.Site}}

Token: {{.Token}}
`

func trim(inp string) string {
	res := strings.ReplaceAll(inp, "\n", "")
	res = strings.TrimSpace(res)

	if len(res) > 128 {
		return res[:128]
	}

	return res
}
