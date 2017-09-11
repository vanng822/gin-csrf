package csrf

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	fmt.Println("Test starting")
	retCode := m.Run()
	fmt.Println("Test ending")
	os.Exit(retCode)
}
