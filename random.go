package csrf

import (
	"crypto/rand"
	"encoding/base64"
	"io"
)

func generateToken(byteLenth int) string {
	result := make([]byte, byteLenth)
	if _, err := io.ReadFull(rand.Reader, result); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(result)
}
