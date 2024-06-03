package direct

import "net/http"

// AuthHandler doesn't do anything for direct login as it has no callbacks
func (p Handler) AuthHandler(http.ResponseWriter, *http.Request) {}
