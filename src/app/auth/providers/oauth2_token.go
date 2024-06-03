package providers

import (
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"strings"
)

// Name returns provider name
func (p Oauth2Handler) Name() string { return p.name }

func (p Oauth2Handler) makeRedirectURL(path string) string {
	elems := strings.Split(path, "/")
	newPath := strings.Join(elems[:len(elems)-1], "/")

	return strings.TrimSuffix(p.URL, "/") + strings.TrimSuffix(newPath, "/") + "/callback"
}

func GenerateRandomToken() (string, error) {
	b := make([]byte, 32)

	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("can't get random: %w", err)
	}

	s := sha1.New()
	if _, err := s.Write(b); err != nil {
		return "", fmt.Errorf("can't write randoms to sha1: %w", err)
	}

	return fmt.Sprintf("%x", s.Sum(nil)), nil
}
