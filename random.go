package csrf

import (
	"crypto/rand"
	"encoding/hex"
	"io"
)

func randomHex(byteLenth int) string {
	result := make([]byte, byteLenth)
	if _, err := io.ReadFull(rand.Reader, result); err != nil {
		panic(err)
	}
	return hex.EncodeToString(result)
}
