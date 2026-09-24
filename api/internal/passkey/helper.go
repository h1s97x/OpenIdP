package passkey

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/h1s97x/openidp/api/internal/auth"
)

// newID generates a random ceremony identifier.
func newID() string {
	return auth.RandomToken(16)
}

// mustHTTPRequest wraps raw credential JSON into an *http.Request whose body
// the webauthn library parses for the Finish* steps.
func mustHTTPRequest(credentialJSON json.RawMessage) *http.Request {
	req, err := http.NewRequest(http.MethodPost, "/", bytes.NewReader(credentialJSON))
	if err != nil {
		panic(err) // constructing an in-memory request cannot fail
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}
