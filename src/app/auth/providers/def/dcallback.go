package def

import "net/http"

// AuthHandler doesn't do anything for direct login as it has no callbacks
func (e DefaultHandler) AuthHandler(http.ResponseWriter, *http.Request) {}
