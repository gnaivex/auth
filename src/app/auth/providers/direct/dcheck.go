package direct

import "net/http"

// UserIDFunc allows to provide custom func making userID instead of the default based on user's name hash
type UserIDFunc func(user string, r *http.Request) string

// CredCheckerFunc type is an adapter to allow the use of ordinary functions as CredsChecker.
type CredCheckerFunc func(user, password string) (ok bool, err error)

// CredChecker defines interface to check credentials
type CredChecker interface {
	Check(user, password string) (ok bool, err error)
}

// Check calls f(user,passwd)
func (f CredCheckerFunc) Check(user, password string) (ok bool, err error) {
	return f(user, password)
}
