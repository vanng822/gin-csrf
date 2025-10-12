package csrf

import (
	"crypto/rand"
	"encoding/base64"
	"io"
)

func generateToken(byteLength int) (string, error) {
	result := make([]byte, byteLength)
	if _, err := io.ReadFull(rand.Reader, result); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(result), nil
}
